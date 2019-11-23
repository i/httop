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
	"time"

	"datadog-project/display"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	port           = flag.Int("port", 80, "Port for which to monitor http traffic")
	displayWindow  = flag.Duration("displayWindow", 10*time.Second, "Size of sliding window to show stats")
	alertWindow    = flag.Duration("alertwindow", 2*time.Minute, "Size of sliding window to alert on")
	alertThreshold = flag.Int("alertThreshold", 100, "Alert on number of hits when this threshold exceeded")
	gui            = flag.Bool("gui", false, "Whether or not to enable full screen mode")
)

func main() {
	flag.Parse()

	go startDebugServer()

	sniffer := &Sniffer{
		Port:           uint16(*port),
		ReportInterval: *displayWindow,
		DisplayWindow:  *displayWindow,
		AlertThreshold: *alertThreshold,
		AlertWindow:    *alertWindow,
		GUIEnabled:     *gui,
	}

	if err := sniffer.Start(); err != nil {
		log.Fatal(err)
	}

	select {}
}

// backup default interface for darwin
const _defaultIface = "en0"

func defaultIface() string {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		return _defaultIface
	}
	return devs[0].Name
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

	displayTick   chan struct{}
	roundTrips    chan roundTripInfo
	stats         map[string][]frame
	stopReporting chan struct{}
}

type frame struct {
	ts   time.Time
	up   int
	down int
}

type roundTripInfo struct {
	host         string
	path         string
	requestSize  int
	responseSize int
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
			panic(err)
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
	for {
		responseSize := tcpreader.DiscardBytesToEOF(r)
		request := <-ch
		var cw countWriter

		if err := request.Write(&cw); err != nil {
			panic(err)
		}

		roundTrips <- roundTripInfo{
			host:         request.Host,
			path:         request.URL.String(),
			requestSize:  int(cw),
			responseSize: responseSize,
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
func (s *Sniffer) Start() error {
	if s.GUIEnabled {
		if err := display.Init(); err != nil {
			return fmt.Errorf("error initializing GUI: %v", err)
		}
	}

	handle, err := pcap.OpenLive(defaultIface(), 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening packet stream: %w", err)
	}

	handle.SetBPFFilter(fmt.Sprintf("tcp port %v", s.Port))
	s.roundTrips = make(chan roundTripInfo, 1)
	s.displayTick = make(chan struct{}, 1)
	s.stats = make(map[string][]frame)

	go s.displayLoop()
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

// not threadsafe
func (s *Sniffer) processRoundTrips() {
	for rt := range s.roundTrips {
		section := sectionFromHostPath(rt.host, rt.path)
		s.stats[section] = append(s.stats[section], frame{
			ts:   time.Now(),
			up:   rt.requestSize,
			down: rt.responseSize,
		})

		if s.GUIEnabled {
			s.displayTick <- struct{}{}
		}
	}
}

func (s *Sniffer) displayLoop() {
	s.stopReporting = make(chan struct{})
	t := time.NewTicker(s.ReportInterval)
	for {
		select {
		case <-s.stopReporting:
			t.Stop()
			return
		case <-s.displayTick:
			s.showDisplay()
		case <-t.C:
			s.showDisplay()
		}
	}
}

func (s *Sniffer) showDisplay() {
	rows := s.collectStats()
	if s.GUIEnabled {
		display.Update(rows)
	} else {
		for _, r := range rows {
			fmt.Println(r)
		}
	}
}

func (s *Sniffer) collectStats() []display.Row {
	now := time.Now()
	displayEpoch := now.Add(-s.DisplayWindow)
	alertEpoch := now.Add(-s.AlertWindow)
	rows := make([]display.Row, 0, len(s.stats))

	for section, frames := range s.stats {
		if len(frames) == 0 {
			// TODO make this threadsafe
			delete(s.stats, section)
			continue
		}

		var displayHits, displayUp, displayDown, displayTotal, alertHits, alertUp, alertDown, alertTotal int
		for i := range frames {
			// this is just iterating backwards
			i = len(frames) - 1 - i
			f := frames[i]

			if f.ts.Before(alertEpoch) {
				// remove this and all the frames preceding it
				s.stats[section] = frames[i+1:]
				break
			}

			alertHits++
			alertUp += f.up
			alertDown += f.down
			alertTotal += alertUp + alertDown

			if f.ts.After(displayEpoch) {
				displayHits++
				displayUp += f.up
				displayDown += f.down
				displayTotal += displayUp + displayDown
			}
		}

		row := display.Row{
			Section: section,
			Hits:    displayHits,
			Up:      displayUp,
			Down:    displayDown,
			Total:   displayTotal,
		}

		if alertHits > s.AlertThreshold {
			row.Alert = true
			rows = append(rows, row)
			continue
		}

		if displayHits > 0 {
			rows = append(rows, row)
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Hits > rows[j].Hits })
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Alert && !rows[j].Alert })
	return rows

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
