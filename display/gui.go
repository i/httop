package display

import (
	"fmt"
	"os"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

type GUI struct {
	table *widgets.Table
}

func (g *GUI) Update(global Row, sections []Row) {
	// preserve headers
	g.table.Rows = g.table.Rows[:1]
	g.table.Rows = append(g.table.Rows, global.AsTableRow())

	for i, row := range sections {
		g.table.Rows = append(g.table.Rows, row.AsTableRow())
		g.table.RowStyles[i+2] = styleRow(row.IsAlerting)
	}

	w, h := ui.TerminalDimensions()
	g.table.SetRect(0, 0, w, h)
	ui.Render(g.table)
}

func styleRow(isAlerting bool) ui.Style {
	if isAlerting {
		return ui.NewStyle(ui.ColorWhite, ui.ColorRed, ui.ModifierBold)
	}
	return ui.NewStyle(ui.ColorWhite, ui.ColorBlack, ui.ModifierBold)
}

type Options struct {
	DisplayWindow time.Duration
	AlertWindow   time.Duration
}

func makeHeaders(options Options) []string {
	return []string{
		"SECTION",
		fmt.Sprintf("HITS (%v)", options.DisplayWindow),
		fmt.Sprintf("HITS (%v)", options.AlertWindow),
		fmt.Sprintf("TOTAL (%v)", options.DisplayWindow),
		fmt.Sprintf("TOTAL (%v)", options.AlertWindow),
		fmt.Sprintf("DOWN (%v)", options.DisplayWindow),
		fmt.Sprintf("DOWN (%v)", options.AlertWindow),
		fmt.Sprintf("UP (%v)", options.DisplayWindow),
		fmt.Sprintf("UP (%v)", options.AlertWindow),
	}
}

func NewGUI(options Options) (*GUI, error) {
	if err := ui.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize gui: %v", err)
	}

	w, h := ui.TerminalDimensions()
	table := widgets.NewTable()
	table.Rows = [][]string{makeHeaders(options), Row{Section: "total"}.AsTableRow()}
	table.RowStyles[1] = styleRow(false)
	table.TextStyle = ui.NewStyle(ui.ColorWhite)
	table.RowSeparator = true
	table.BorderStyle = ui.NewStyle(ui.ColorGreen)
	table.SetRect(0, 0, w, h)
	table.FillRow = true

	ui.Render(table)

	go func() {
		for e := range ui.PollEvents() {
			switch e.ID {
			case "q", "<C-c>":
				ui.Close()
				os.Exit(0)
				return
			}
		}
	}()

	return &GUI{table: table}, nil
}

func (g *GUI) Close() {
	ui.Close()
}
