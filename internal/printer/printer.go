package printer

import (
	"fmt"
	"log"

	"github.com/marko-gacesa/fenc/internal/task"

	"github.com/fatih/color"
)

const (
	colorNorm = iota
	colorEnc
	colorDec
	colorSrc
	colorDst
	colorDone
	colorFail
	colorErr
	lenColors
)

type Printer struct {
	suppress bool
	wIn      int
	wOut     int
	colors   []*color.Color
}

func MakePrinter(suppress, noColor bool) *Printer {
	if suppress {
		return &Printer{
			suppress: true,
		}
	}

	colors := make([]*color.Color, lenColors)
	colors[colorNorm] = color.New(color.FgWhite)
	colors[colorEnc] = color.New(color.FgMagenta)
	colors[colorDec] = color.New(color.FgYellow)
	colors[colorSrc] = color.New(color.FgCyan)
	colors[colorDst] = color.New(color.FgCyan)
	colors[colorDone] = color.New(color.FgGreen)
	colors[colorFail] = color.New(color.FgRed)
	colors[colorErr] = color.New(color.FgHiRed)

	if noColor {
		for i := range colors {
			colors[i].DisableColor()
		}
	}

	return &Printer{colors: colors}
}

func (p *Printer) SetWidths(wIn, wOut int) {
	p.wIn = wIn
	p.wOut = wOut
}

func (p *Printer) PrintTask(t *task.Task) {
	if p.suppress {
		return
	}

	p.colors[colorNorm].Print("")

	const (
		procEnc = "encrypt"
		procDec = "decrypt"
	)
	if t.ProcEnc {
		p.colors[colorEnc].Print(procEnc)
	} else {
		p.colors[colorDec].Print(procDec)
	}
	p.colors[colorNorm].Print(": ")

	p.colors[colorSrc].Printf("%-*s", p.wIn, t.InputFile)
	if t.RemoveInput {
		p.colors[colorNorm].Print(" ==> ")
	} else {
		p.colors[colorNorm].Print(" --> ")
	}
	p.colors[colorDst].Printf("%-*s", p.wOut, t.OutputFile)
}

func (p *Printer) PrintLn() {
	if p.suppress {
		return
	}

	p.colors[colorNorm].Println()
}

func (p *Printer) PrintDone() {
	if p.suppress {
		return
	}

	p.colors[colorNorm].Print(" ")
	p.colors[colorDone].Print("DONE")
	p.colors[colorNorm].Print(" ")
}

func (p *Printer) PrintFail() {
	if p.suppress {
		return
	}

	p.colors[colorNorm].Print(" ")
	p.colors[colorFail].Print("FAIL")
	p.colors[colorNorm].Print(" ")
}

func (p *Printer) PrintError(err error, format string, args ...any) {
	if err == nil {
		return
	}

	msg := fmt.Sprintf(format, args...)
	if p.suppress {
		log.Printf("%s: %s", msg, err.Error())
		return
	}

	p.colors[colorErr].Printf("\n%s: %s", msg, err.Error())
}
