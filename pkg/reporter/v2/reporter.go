package v2

import (
	"context"
	"fmt"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
)

const EngineVersion = "6"

type ReportOutput string

var (
	REPORT_BASIC    ReportOutput = "basic"
	REPORT_JSON     ReportOutput = "json"
	REPORT_DETAILED ReportOutput = "detailed"
)

type Reporter struct {
	Ctx        context.Context
	Results    []api.Result
	ReportType ReportOutput
}

func NewReport(ctx context.Context, results []api.Result, rFormat string) *Reporter {
	report := &Reporter{
		Ctx:        ctx,
		Results:    results,
		ReportType: ReportOutput(rFormat),
	}

	return report
}

func (r *Reporter) Report() {
	switch r.ReportType {

	case REPORT_BASIC:
		r.basicReport()

	case REPORT_JSON:
		o, err := r.jsonReport()
		if err != nil {
			fmt.Printf("json report error: %v\n", err)
			return
		}
		fmt.Println(o)

	case REPORT_DETAILED:
		r.detailedReport()

	default:
		fmt.Print("Unknow Report type")
	}
}
