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
	Up      int
	Down    int
	Total   int
	Alert   bool
}

func Update(rows []Row) {
	w, h := ui.TerminalDimensions()
	table.SetRect(0, 0, w, h)
	table.Rows = table.Rows[:1]
	for i, row := range rows {
		table.Rows = append(table.Rows, []string{
			" " + row.Section + " ",
			strconv.Itoa(row.Hits),
			strconv.Itoa(row.Total),
			strconv.Itoa(row.Down),
			strconv.Itoa(row.Up),
		})
		table.RowStyles[i] = ui.NewStyle(ui.ColorWhite, ui.ColorBlack, ui.ModifierBold)
		if row.Alert {
			table.RowStyles[i] = ui.NewStyle(ui.ColorWhite, ui.ColorRed, ui.ModifierBold)
		}
	}
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
