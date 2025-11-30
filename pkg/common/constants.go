// Package common provides shared constants, utilities, and common functionality
// used across the sbomqs application.
package common

const (
	// SBOM format and specification types
	FormatSPDX      = "spdx"
	FormatCycloneDX = "cyclonedx"
	FormatJSON      = "json"
	FormatXML       = "xml"
	FormatYAML      = "yaml"
	FormatYML       = "yml"
	FormatTagValue  = "tag-value"
	FormatText      = "text"

	// Report types
	ReportBasic    = "basic"
	ReportDetailed = "detailed"

	// SBOM spec versions
	Version14 = "1.4"
	Version15 = "1.5"
	Version16 = "1.6"

	// Score thresholds
	ScorePerfect = 100.0
	ScoreGood    = 80.0
	ScoreFair    = 60.0
	ScorePoor    = 40.0
	ScoreVeryPoor = 20.0

	// Common field names
	FieldName        = "name"
	FieldVersion     = "version"
	FieldSupplier    = "supplier"
	FieldAuthor      = "author"
	FieldLicense     = "license"
	FieldChecksum    = "checksum"
	FieldTimestamp   = "timestamp"
	FieldComponent   = "component"
	FieldDependency  = "dependency"
	FieldRelationship = "relationship"
)