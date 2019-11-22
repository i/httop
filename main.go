package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// backup default interface for darwin
const _defaultIface = "en0"

func defaultIface() string {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		return _defaultIface
	}
	return devs[0].Name
}

func main() {
	go startDebugServer()

	sniffer := &Sniffer{
		Ports:          []uint16{80},
		ReportInterval: time.Second * 5,
	}

	if err := sniffer.Start(); err != nil {
		log.Fatal(err)
	}

	select {}

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
	Ports          []uint16
	ReportInterval time.Duration

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

func isHTTPResponse(r *bufio.Reader) bool {
	bb, err := r.Peek(4)
	fmt.Println(err, string(bb))
	return err == nil && string(bb) == "HTTP"
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
}

func (s *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	r.ReaderStreamOptions = tcpreader.ReaderStreamOptions{
		LossErrors: true,
	}

	// handle outgoing request
	if tcpFlow.Dst().String() == "80" {
		hostport := fmt.Sprintf("%s:%s", netFlow.Dst().String(), tcpFlow.Src().String())
		ch := make(chan *http.Request, 100)
		s.pending[hostport] = ch
		fmt.Println("put in", hostport)
		go processRequests(&r, ch)
		return &r
	}

	// handle response
	if tcpFlow.Src().String() == "80" {
		hostport := fmt.Sprintf("%s:%s", netFlow.Src().String(), tcpFlow.Dst().String())
		ch, ok := s.pending[hostport]
		if !ok {
			fmt.Println("couldn't find", hostport)
			handleUnexpectedResponse(&r)
			return &r
		}
		go processResponses(&r, ch, s.roundTrips)
		return &r
	}

	panic("this shouldn't happen")
}

func (s *Sniffer) Start() error {
	handle, err := pcap.OpenLive(defaultIface(), 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening packet stream: %w", err)
	}

	handle.SetBPFFilter("tcp port 80") // TODO make this configurable
	s.roundTrips = make(chan roundTripInfo, 1)
	s.stats = make(map[string][]frame)

	go s.displayLoop()
	go s.processRoundTrips()
	go s.getPackets(handle)

	return nil
}

func (s *Sniffer) getPackets(h *pcap.Handle) {
	streamFactory := &httpStreamFactory{
		pending:    make(map[string]chan *http.Request),
		roundTrips: s.roundTrips,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	packets := packetSource.Packets()
	for {
		select {
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
		s.ShowDisplay()
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
		case <-t.C:
			s.ShowDisplay()
		}
	}
}

func (s *Sniffer) ShowDisplay() {
	now := time.Now()
	showTS := now.Add(-time.Second * 5)
	alertTS := now.Add(-time.Second * 10) // TODO make this 2 minutes or configurable

	var rows []displayRow

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

			if f.ts.Before(alertTS) {
				// remove this and all the frames preceding it
				s.stats[section] = frames[i+1:]
				break
			}

			alertHits++
			alertUp += f.up
			alertDown += f.down
			alertTotal += alertUp + alertDown

			if f.ts.After(showTS) {
				displayHits++
				displayUp += f.up
				displayDown += f.down
				displayTotal += displayUp + displayDown
			}
		}
		if displayHits > 0 {
			rows = append(rows, displayRow{
				Section: section,
				Hits:    displayHits,
				Up:      displayUp,
				Down:    displayDown,
				Total:   displayTotal,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Hits > rows[j].Hits
	})
	for _, row := range rows {
		fmt.Println(row)
	}
}

type displayRow struct {
	Section string
	Hits    int
	Up      int
	Down    int
	Total   int
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
