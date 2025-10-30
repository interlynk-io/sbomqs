package v2

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
)

func (r *Reporter) detailedReport() {
	fmt.Println("DETAILED SCORE")
	for _, r := range r.Results {
		outDoc := [][]string{}
		for _, cat := range r.Comprehensive.Categories {
			for _, feat := range cat.Features {
				l := []string{cat.Name, feat.Key, fmt.Sprintf("%.1f/10.0", feat.Score), feat.Desc}
				outDoc = append(outDoc, l)
			}
		}

		fmt.Printf("\n  SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d\t%s\t\n\n", r.InterlynkScore, r.Grade, r.Meta.NumComponents, r.Meta.Filename)

		// Initialize tablewriter table with borders
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Category", "Feature", "Score", "Desc"})
		table.SetRowLine(true)
		table.SetAutoMergeCellsByColumnIndex([]int{0})
		table.AppendBulk(outDoc)
		table.Render()
	}
}
