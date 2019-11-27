package display

import (
	"bufio"
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAlerts(t *testing.T) {
	alertWindow := time.Second * 5
	var b bytes.Buffer
	br := bufio.NewReader(&b)
	clockTime := time.Now()

	d := NewText(Options{AlertWindow: alertWindow})
	d.Output = &b
	d.clock = func() time.Time {
		return clockTime
	}

	// set two alerts to be active
	d.Update(Row{Section: "global"}, []Row{
		{Section: "section1", DisplayHits: 1, IsAlerting: true},
		{Section: "section2", DisplayHits: 1, IsAlerting: true},
	})
	expectStringContains(t, br, "HITS\tTotal\tDown\tUp\tSection")
	expectStringContains(t, br, "0\t0B\t0B\t0B\tglobal")
	expectStringContains(t, br, "1\t0B\t0B\t0B\tsection1")
	expectStringContains(t, br, "1\t0B\t0B\t0B\tsection2")
	expectStringContains(t, br, "High traffic to section1 generated an alert - hits = 0, triggered at")
	expectStringContains(t, br, "High traffic to section2 generated an alert - hits = 0, triggered at")
	expectStringContains(t, br, "")

	// clear one alert by setting IsAlerting to false
	clockTime = clockTime.Add(alertWindow + 1)
	d.Update(Row{Section: "global"}, []Row{
		{Section: "section1", DisplayHits: 1, IsAlerting: true},
		{Section: "section2", DisplayHits: 1, IsAlerting: false},
	})
	expectStringContains(t, br, "HITS\tTotal\tDown\tUp\tSection")
	expectStringContains(t, br, "0\t0B\t0B\t0B\tglobal")
	expectStringContains(t, br, "1\t0B\t0B\t0B\tsection1")
	expectStringContains(t, br, "1\t0B\t0B\t0B\tsection2")
	expectStringContains(t, br, "High traffic to section2 recovered after")
	expectStringEquals(t, br, "")

	clockTime = clockTime.Add(alertWindow + 1)

	// not sending the row in an should also clear the alert
	d.Update(Row{Section: "global"}, []Row{})
	expectStringContains(t, br, "HITS\tTotal\tDown\tUp\tSection")
	expectStringContains(t, br, "0\t0B\t0B\t0B\tglobal")
	expectStringContains(t, br, "High traffic to section1 recovered after")
	expectStringContains(t, br, "")
}

func expectStringEquals(t *testing.T, b *bufio.Reader, s string) {
	out, err := b.ReadString('\n')
	assert.NoError(t, err)
	assert.Equal(t, out, s+"\n")
}
func expectStringContains(t *testing.T, b *bufio.Reader, s string) {
	out, err := b.ReadString('\n')
	assert.NoError(t, err)
	assert.Contains(t, out, s)
}
