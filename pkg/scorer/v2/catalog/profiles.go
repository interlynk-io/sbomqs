package catalog

import "github.com/interlynk-io/sbomqs/pkg/sbom"

// ProfSpec represents specification of each profiles.
// e.g. ntia, bsi-v1.1, bsi-v2.0, oct, etc
type ProfSpec struct {
	Name        string
	Description string
	Key         ProfileKey
	Features    []ProfFeatKey
}

// ProfFeatSpec represents specification of feature of each profiles.
type ProfFeatSpec struct {
	Name        string
	Required    bool
	Description string
	Key         ProfFeatKey
	Evaluate    ProfFeatEval
}

// ProfFeatEval represents evaluation of corresponding feature.
type ProfFeatEval func(doc sbom.Document) ProfFeatScore

// ProfFeatScore carries score of a profiles feature
type ProfFeatScore struct {
	Score  float64
	Desc   string
	Ignore bool
}

type ProfComplianceState string
