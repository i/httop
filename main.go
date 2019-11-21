package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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

func defaultDevice() string {
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

	sniffer.Start()
}

type Sniffer struct {
	Interface      string
	Ports          []uint16
	ReportInterval time.Duration

	data          map[string]interface{}
	stopReporting chan struct{}
}

type httpStreamFactory struct{}

func isHTTPResponse(r *bufio.Reader) bool {
	bb, err := r.Peek(4)
	return err == nil && string(bb) == "HTTP"
}

func (s *Sniffer) processRequests(r io.Reader) {
	buf := bufio.NewReader(r)
	for {
		if isHTTPResponse(buf) {
			bb, err := ioutil.ReadAll(buf)
			if err != nil {
				log.Fatalf("Error reading http response: %v", err)
			}
			fmt.Println(string(bb))
			fmt.Printf("Response body contains: %v bytes\n", len(bb))
			continue
		}
		req, err := http.ReadRequest(buf)
		if err != nil {
			return
		}
		if err == io.EOF {
			return
		}
		fmt.Printf("HTTP REQUEST: %+v", req)
		fmt.Println("Body contains", tcpreader.DiscardBytesToEOF(req.Body), "bytes")
	}
}

func (s *httpStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processRequests(&r)
	return &r
}

func (s *Sniffer) Start() error {
	handle, err := pcap.OpenLive(defaultDevice(), 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening packet stream: %w", err)
	}

	go s.displayLoop()

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}

		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

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
