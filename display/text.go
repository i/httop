package display

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"code.cloudfoundry.org/bytefmt"
)

type Text struct {
	Output      io.WriteCloser
	alerts      map[string]alert
	alertWindow time.Duration

	sync.Mutex
}

func (r Row) String() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s",
		strconv.Itoa(r.DisplayHits),
		bytefmt.ByteSize(uint64(r.DisplayTotal)),
		bytefmt.ByteSize(uint64(r.DisplayDown)),
		bytefmt.ByteSize(uint64(r.DisplayUp)),
		r.Section,
	)
}

type alert struct {
	section   string
	firstSeen time.Time
	lastSeen  time.Time
}

func NewText(opts Options) *Text {
	return &Text{
		Output:      os.Stdout,
		alerts:      make(map[string]alert),
		alertWindow: opts.AlertWindow,
	}
}

func (t *Text) Update(global Row, sections []Row) {
	t.Lock()
	defer t.Unlock()

	now := time.Now()
	fmt.Fprintf(os.Stdout, "HITS\tTotal\tDown\tUp\tSection\n")
	fmt.Fprintln(t.Output, global)
	var newAlerts []string
	for _, r := range sections {
		if r.IsAlerting {
			a, ok := t.alerts[r.Section]
			if !ok {
				a = alert{section: r.Section, firstSeen: now}
				newAlerts = append(newAlerts, fmt.Sprintf(
					"High traffic to %s generated an alert - hits = %d, triggered at %v",
					r.Section, r.AlertHits, now.Format(time.RFC3339)))
			}
			a.lastSeen = now
			t.alerts[r.Section] = a
		}

		if r.DisplayHits > 0 {
			fmt.Fprintln(t.Output, r)
		}
	}

	for _, a := range newAlerts {
		fmt.Println(a)
	}

	for _, a := range t.removeRecoveredAlerts() {
		fmt.Fprintf(t.Output, "High traffic to %s recovered after %v\n", a.section, time.Since(a.firstSeen))
	}

	fmt.Fprintln(t.Output)
}

func (t *Text) removeRecoveredAlerts() []alert {
	now := time.Now()
	var ret []alert
	for section, alert := range t.alerts {
		if now.Sub(alert.lastSeen) > t.alertWindow {
			delete(t.alerts, section)
			ret = append(ret, alert)
		}
	}
	return ret
}
