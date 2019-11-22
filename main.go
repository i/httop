package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"runtime"
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
	sniffer := &Sniffer{
		Ports:          []uint16{80},
		ReportInterval: time.Second * 5,
	}

	go startDebugServer()
	sniffer.Start()
}

func startDebugServer() {
	runtime.SetBlockProfileRate(1)
	go http.ListenAndServe(":8080", nil)
}

type Sniffer struct {
	Interface      string
	Ports          []uint16
	ReportInterval time.Duration

	address       []string
	data          map[string]interface{}
	stopReporting chan struct{}
}

func isHTTPResponse(r *bufio.Reader) bool {
	bb, err := r.Peek(4)
	fmt.Println(err, string(bb))
	return err == nil && string(bb) == "HTTP"
}

func processRequests(r io.Reader, ch chan *http.Request) {
	buf := bufio.NewReader(r)
	for {
		fmt.Println(66)
		req, err := http.ReadRequest(buf)
		fmt.Println(69)
		if err == io.EOF {
			return
		}
		if err != nil {
			panic(err)
		}

		fmt.Println("putting it in")
		ch <- req
		fmt.Println("put it in")
	}
}

func processResponses(r io.Reader, ch chan *http.Request) error {
	buf := bufio.NewReader(r)
	for {
		bb, err := ioutil.ReadAll(buf)
		if err == io.EOF || (err == nil && len(bb) == 0) {
			return nil
		}
		if err != nil {
			log.Fatalf("Error reading http response: %v", err)
		}
		// fmt.Println(string(bb))
		fmt.Printf("Response body contains: %v bytes\n", len(bb))
		request := <-ch
		fmt.Println("SUCCESS", request)
	}
}

type httpRequestResponse struct {
	host    string
	section string
	size    string
}

type httpStreamFactory struct {
	pending map[string]chan *http.Request
}

func (s *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()

	// handle outgoing request
	if tcpFlow.Dst().String() == "80" {
		ch := make(chan *http.Request, 1)

		host := netFlow.Dst().String()
		port := tcpFlow.Src().String()
		s.pending[fmt.Sprintf("%s:%s", host, port)] = ch
		go processRequests(&r, ch)
		return &r
	}

	// handle response
	if tcpFlow.Src().String() == "80" {
		host := netFlow.Src().String()
		port := tcpFlow.Dst().String()
		ch, ok := s.pending[fmt.Sprintf("%s:%s", host, port)]
		if !ok {
			log.Fatal("no corresponding request for this response")
		}
		go processResponses(&r, ch)
		return &r
	}

	panic("TODO: handle why we're here")
}

func (s *Sniffer) Start() error {
	handle, err := pcap.OpenLive(defaultIface(), 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening packet stream: %w", err)
	}
	handle.SetBPFFilter("tcp port 80")

	// go s.displayLoop()

	streamFactory := &httpStreamFactory{pending: make(map[string]chan *http.Request)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}
		assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
	}
	return nil
}

func (s *Sniffer) displayLoop() {
	s.stopReporting = make(chan struct{})
	t := time.NewTicker(s.ReportInterval)
	for {
		select {
		case <-s.stopReporting:
			return
		case <-t.C:
			s.ShowDisplay()
		}
	}
}

func (s *Sniffer) ShowDisplay() {
	fmt.Println("stats: nil")
}

func sectionFromURL(u string) (string, error) {
	url, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	if url.Path == "" {
		url.Path = "/"
	}
	path := strings.Join(strings.Split(url.Path, "/")[:2], "/")
	return fmt.Sprintf("%s://%s%s", url.Scheme, url.Host, path), nil
}

func uint16SliceContains(haystack []uint16, needle uint16) bool {
	for _, e := range haystack {
		if e == needle {
			return true
		}
	}
	return false
}
