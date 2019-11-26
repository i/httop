package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"datadog-project/display"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	iface          = flag.String("iface", "", "Device for which to monitor traffic")
	port           = flag.Int("port", 80, "Port for which to monitor http traffic")
	displayWindow  = flag.Duration("displayWindow", 10*time.Second, "Size of sliding window to show stats")
	alertWindow    = flag.Duration("alertWindow", 2*time.Minute, "Size of sliding window to alert on")
	alertThreshold = flag.Int("alertThreshold", 100, "Alert on number of hits when this threshold exceeded")
	gui            = flag.Bool("gui", false, "Whether or not to enable full screen mode")
	debug          = flag.Bool("debug", false, "Whether or not to mount pprof endpoints for debugging")
)

func main() {
	flag.Parse()

	if *debug {
		go startDebugServer()
	}

	sniffer := &Sniffer{
		Port:           uint16(*port),
		ReportInterval: *displayWindow,
		DisplayWindow:  *displayWindow,
		AlertThreshold: *alertThreshold,
		AlertWindow:    *alertWindow,
		GUIEnabled:     *gui,
	}

	if err := sniffer.Start(*iface, uint16(*port)); err != nil {
		log.Fatal(err)
	}

	select {}
}

func defaultIface() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		return "", err
	}
	return devs[0].Name, nil
}

func startDebugServer() {
	runtime.SetBlockProfileRate(1)
	go http.ListenAndServe(":8080", nil)
}

type countWriter int64

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := ioutil.Discard.Write(p)
	*cw += countWriter(n)
	return n, err
}

type Sniffer struct {
	Interface      string
	Port           uint16
	ReportInterval time.Duration
	AlertThreshold int
	AlertWindow    time.Duration
	DisplayWindow  time.Duration
	GUIEnabled     bool

	display       display.Display
	displayTick   chan struct{}
	roundTrips    chan roundTripInfo
	stopReporting chan struct{}

	stats map[string][]roundTripInfo

	sync.Mutex
}

type roundTripInfo struct {
	host         string
	path         string
	requestSize  int
	responseSize int
	timestamp    time.Time
}

func processRequests(r io.ReadCloser, ch chan *http.Request) {
	defer r.Close()

	buf := bufio.NewReader(r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		}
		if err != nil {
			// possible malformed http request
			tcpreader.DiscardBytesToEOF(r)
			return
		}
		ch <- req
	}
}

func handleUnexpectedResponse(r io.ReadCloser) {
	// TODO any operation on r will block forever which blocks assembly for the
	// rest of the streams.
	return
}

func processResponses(r io.ReadCloser, ch chan *http.Request, roundTrips chan<- roundTripInfo) {
	defer r.Close()

	buf := bufio.NewReader(r)
	for {
		cw1, err := buf.WriteTo(ioutil.Discard)
		if err != nil {
			panic(err)
		}

		request := <-ch
		var cw countWriter

		if err := request.Write(&cw); err != nil {
			panic(err)
		}

		roundTrips <- roundTripInfo{
			host:         request.Host,
			path:         request.URL.String(),
			requestSize:  int(cw),
			responseSize: int(cw1),
			timestamp:    time.Now(),
		}
	}
}

type httpStreamFactory struct {
	pending    map[string]chan *http.Request
	roundTrips chan roundTripInfo
	port       string
}

func (s *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	r.ReaderStreamOptions = tcpreader.ReaderStreamOptions{
		LossErrors: true,
	}

	// handle outgoing request
	if tcpFlow.Dst().String() == s.port {
		hostport := fmt.Sprintf("%s:%s", netFlow.Dst().String(), tcpFlow.Src().String())
		ch := make(chan *http.Request, 100)
		s.pending[hostport] = ch
		go processRequests(&r, ch)
	}

	// handle response
	if tcpFlow.Src().String() == s.port {
		hostport := fmt.Sprintf("%s:%s", netFlow.Src().String(), tcpFlow.Dst().String())
		ch, ok := s.pending[hostport]
		if !ok {
			handleUnexpectedResponse(&r)
			return &r
		}
		go processResponses(&r, ch, s.roundTrips)
	}

	return &r
}

// Start is the main entrypoint for a sniffer
func (s *Sniffer) Start(iface string, port uint16) error {
	if s.GUIEnabled {
		disp, err := display.NewGUI(display.Options{DisplayWindow: s.DisplayWindow, AlertWindow: s.AlertWindow})
		if err != nil {
			return fmt.Errorf("error initializing GUI: %v", err)
		}
		s.display = disp
	} else {
		s.display = display.NewText(display.Options{DisplayWindow: s.DisplayWindow, AlertWindow: s.AlertWindow})
	}

	if iface == "" {
		i, err := defaultIface()
		if err != nil {
			log.Fatalf("Unable to list devices: %v", err)
		}
		iface = i
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening packet stream: %w", err)
	}

	handle.SetBPFFilter(fmt.Sprintf("tcp port %d", s.Port))
	s.roundTrips = make(chan roundTripInfo, 1)
	s.displayTick = make(chan struct{}, 1)
	s.stats = make(map[string][]roundTripInfo)

	go s.displayLoop()
	go s.startDisplayTimer()
	go s.processRoundTrips()
	go s.getPackets(handle)

	return nil
}

func (s *Sniffer) getPackets(h *pcap.Handle) {
	streamFactory := &httpStreamFactory{
		port:       strconv.Itoa(int(s.Port)),
		pending:    make(map[string]chan *http.Request),
		roundTrips: s.roundTrips,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	packets := packetSource.Packets()

	t := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-t.C:
			assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: true})
		case <-s.stopReporting:
			// TODO cleanup?
			return
		case packet := <-packets:
			tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok {
				continue
			}
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
		}
	}
}

func (s *Sniffer) processRoundTrips() {
	for rt := range s.roundTrips {
		section := sectionFromHostPath(rt.host, rt.path)

		s.Lock()
		s.stats[section] = append(s.stats[section], rt)
		s.trimStats(section)
		s.Unlock()

		if s.GUIEnabled {
			s.displayTick <- struct{}{}
		}
	}
}

func (s *Sniffer) trimStats(section string) {
	stats := s.stats[section]
	alertEpoch := time.Now().Add(-s.AlertWindow)
	for i := range stats {
		f := stats[len(stats)-1-i]
		if f.timestamp.Before(alertEpoch) {
			s.stats[section] = stats[len(stats)-1-i:]
			return
		}
	}
}

func (s *Sniffer) startDisplayTimer() {
	t := time.NewTicker(s.ReportInterval)
	for range t.C {
		s.displayTick <- struct{}{}
	}
}

func (s *Sniffer) displayLoop() {
	for range s.displayTick {
		s.showDisplay()
	}
}

func (s *Sniffer) showDisplay() {
	stats := s.collectStats()
	s.display.Update(stats.Global, stats.Sections)
}

type Stats struct {
	Global   display.Row
	Sections []display.Row
}

func (s *Sniffer) collectStats() Stats {
	now := time.Now()
	displayEpoch := now.Add(-s.DisplayWindow)
	alertEpoch := now.Add(-s.AlertWindow)
	rows := make([]display.Row, 0, len(s.stats))

	for section, frames := range s.stats {
		row := display.Row{Section: section}
		for i := range frames {
			f := frames[len(frames)-1-i]

			if f.timestamp.Before(alertEpoch) {
				break
			}

			row.AlertHits++
			row.AlertUp += f.requestSize
			row.AlertDown += f.responseSize
			row.AlertTotal += row.AlertUp + row.AlertDown

			if f.timestamp.After(displayEpoch) {
				row.DisplayHits++
				row.DisplayUp += f.requestSize
				row.DisplayDown += f.responseSize
				row.DisplayTotal += row.DisplayUp + row.DisplayDown
			}
		}

		if row.AlertHits == 0 {
			break
		}

		if row.AlertHits > s.AlertThreshold {
			row.IsAlerting = true
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].DisplayHits > rows[j].DisplayHits })
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].IsAlerting && !rows[j].IsAlerting })

	return Stats{
		Global:   aggregate(rows),
		Sections: rows,
	}
}

func aggregate(rows []display.Row) display.Row {
	ret := display.Row{Section: "global"}
	for _, r := range rows {
		ret.DisplayHits += r.DisplayHits
		ret.DisplayUp += r.DisplayUp
		ret.DisplayDown += r.DisplayDown
		ret.DisplayTotal += r.DisplayTotal
		ret.AlertHits += r.AlertHits
		ret.AlertUp += r.AlertUp
		ret.AlertDown += r.AlertDown
		ret.AlertTotal += r.AlertTotal
	}
	return ret
}

func sectionFromHostPath(host, path string) string {
	if path == "" {
		path = "/"
	}
	path = strings.Join(strings.Split(path, "/")[:2], "/")
	return fmt.Sprintf("%s%s", host, path)
}

func uint16SliceContains(haystack []uint16, needle uint16) bool {
	for _, e := range haystack {
		if e == needle {
			return true
		}
	}
	return false
}
