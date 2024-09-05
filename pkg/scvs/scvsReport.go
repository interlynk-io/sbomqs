package scvs

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/olekukonko/tablewriter"
)

type ScvsReporter struct {
	Ctx context.Context

	Docs   []sbom.Document
	Scores []ScvsScores
	Paths  []string

	// optional params
	Format string
}
type Option func(r *ScvsReporter)

func WithFormat(c string) Option {
	return func(r *ScvsReporter) {
		r.Format = c
	}
}

func NewScvsReport(ctx context.Context, doc []sbom.Document, scores []ScvsScores, paths []string, opts ...Option) *ScvsReporter {
	r := &ScvsReporter{
		Ctx:    ctx,
		Docs:   doc,
		Scores: scores,
		Paths:  paths,
	}
	return r
}

func (r *ScvsReporter) ScvsReport() {
	r.detailedScvsReport()
}

func (r *ScvsReporter) detailedScvsReport() {
	for index := range r.Paths {
		// doc := r.Docs[index]
		scores := r.Scores[index]

		outDoc := [][]string{}

		for _, score := range scores.ScoreList() {
			var l []string

			l = []string{score.Feature(), score.L1Score(), score.L2Score(), score.L3Score(), score.Descr()}

			outDoc = append(outDoc, l)
		}

		sort.Slice(outDoc, func(i, j int) bool {
			switch strings.Compare(outDoc[i][0], outDoc[j][0]) {
			case -1:
				return true
			case 1:
				return false
			}
			return outDoc[i][1] < outDoc[j][1]
		})

		// fmt.Printf("SBOM Quality by Interlynk Score:%0.1f\tcomponents:%d\t%s\n", scores.AvgScore(), len(doc.Components()), path)
		fmt.Println("Analysis of SCVS Report by OWASP Organization using SBOMQS Tool")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Feature", "Level 1", "Level 2", "Level 3", "Desc"})
		table.SetRowLine(true)
		table.SetAutoWrapText(false)
		table.SetColMinWidth(0, 60)
		table.SetAutoMergeCellsByColumnIndex([]int{0})
		table.AppendBulk(outDoc)
		table.Render()
	}
}
