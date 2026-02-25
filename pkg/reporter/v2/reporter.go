package v2

import (
	"context"
	"fmt"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
)

const EngineVersion = "6"

type ReportFormat string

var (
	REPORT_BASIC    ReportFormat = "basic"
	REPORT_JSON     ReportFormat = "json"
	REPORT_DETAILED ReportFormat = "detailed"
)

type Reporter struct {
	Ctx     context.Context
	Results []api.Result
	Format  ReportFormat
}

func NewReport(ctx context.Context, results []api.Result, rFormat string) *Reporter {
	report := &Reporter{
		Ctx:     ctx,
		Results: results,
		Format:  ReportFormat(rFormat),
	}

	return report
}

func (r *Reporter) Report() {
	switch r.Format {
	case REPORT_BASIC:
		r.basicReport()

	case REPORT_JSON:
		r.jsonReport()

	case REPORT_DETAILED:
		r.detailedReport()

	default:
		fmt.Print("Unknow Report format")
	}
}
