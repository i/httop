package display

import (
	"fmt"
	"strconv"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

var table *widgets.Table

type Row struct {
	Section string
	Hits    int
	Down    int
	Up      int
	Total   int
	Alert   bool
}

func (r Row) String() string {
	return fmt.Sprintf("%s\t%d\t%d\t%d\t%d",
		r.Section,
		r.Hits,
		r.Down,
		r.Up,
		r.Total)
}

func Update(rows []Row) {
	// preserve headers
	table.Rows = table.Rows[:1]

	for i, row := range rows {
		table.Rows = append(table.Rows, []string{
			row.Section,
			strconv.Itoa(row.Hits),
			strconv.Itoa(row.Total),
			strconv.Itoa(row.Down),
			strconv.Itoa(row.Up),
		})
		table.RowStyles[i+1] = ui.NewStyle(ui.ColorWhite, ui.ColorBlack, ui.ModifierBold)
		if row.Alert {
			table.RowStyles[i+1] = ui.NewStyle(ui.ColorWhite, ui.ColorRed, ui.ModifierBold)
		}
	}

	w, h := ui.TerminalDimensions()
	table.SetRect(0, 0, w, h)
	ui.Render(table)
}

func Init() error {
	if err := ui.Init(); err != nil {
		return fmt.Errorf("failed to initialize termui: %v", err)
	}

	w, h := ui.TerminalDimensions()
	table = widgets.NewTable()
	table.Rows = [][]string{{"SECTION", "HITS (10s)", "TOTAL (10s)", "DOWN (10s)", "UP (10s)"}}
	table.TextStyle = ui.NewStyle(ui.ColorWhite)
	table.RowSeparator = true
	table.BorderStyle = ui.NewStyle(ui.ColorGreen)
	table.SetRect(0, 0, w, h)
	table.FillRow = true
	ui.Render(table)

	go func() {
		defer ui.Close()
		for e := range ui.PollEvents() {
			switch e.ID {
			case "q", "<C-c>":
				return
			}
		}
	}()
	return nil
}
