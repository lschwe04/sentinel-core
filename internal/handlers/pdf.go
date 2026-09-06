package handlers

import (
	"fmt"
	"io"
	"time"

	"github.com/go-pdf/fpdf"
)

func writePDF(w io.Writer, title string, lines []string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(title, false)
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 10, title)
		pdf.Ln(12)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.CellFormat(0, 10, fmt.Sprintf("SentinelCore | %s | Seite %d", time.Now().UTC().Format("2006-01-02"), pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AddPage()
	pdf.SetFont("Arial", "", 10)
	for _, line := range lines {
		pdf.MultiCell(0, 6, line, "", "L", false)
	}
	return pdf.Output(w)
}
