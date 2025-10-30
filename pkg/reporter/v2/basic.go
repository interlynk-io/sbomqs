package v2

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func (r *Reporter) basicReport() {
	for _, r := range r.Results {
		format := r.Meta.FileFormat
		spec := r.Meta.Spec
		version := r.Meta.SpecVersion

		if spec == string(sbom.SBOMSpecSPDX) {
			version = strings.Replace(version, "SPDX-", "", 1)
		}

		// if spec == string(sbom.SBOMSpecCDX) {
		// 	spec = "cyclonedx"
		// }

		fmt.Printf("%0.1f\t%s\t%s\t%s\t%s\n", r.InterlynkScore, r.Grade, version, format, r.Meta.Filename)

	}
}
