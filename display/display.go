package display

import (
	"strconv"

	"code.cloudfoundry.org/bytefmt"
)

type Display interface {
	Update(global Row, sections []Row)
}

type Row struct {
	Section    string
	IsAlerting bool

	// display
	DisplayHits  int
	DisplayUp    int
	DisplayDown  int
	DisplayTotal int

	// alerts
	AlertHits  int
	AlertUp    int
	AlertDown  int
	AlertTotal int
}

func (r Row) AsTableRow() []string {
	return []string{
		r.Section,
		strconv.Itoa(r.DisplayHits),
		strconv.Itoa(r.AlertHits),
		bytefmt.ByteSize(uint64(r.DisplayTotal)),
		bytefmt.ByteSize(uint64(r.AlertTotal)),
		bytefmt.ByteSize(uint64(r.DisplayDown)),
		bytefmt.ByteSize(uint64(r.AlertDown)),
		bytefmt.ByteSize(uint64(r.DisplayUp)),
		bytefmt.ByteSize(uint64(r.AlertUp)),
	}
}
