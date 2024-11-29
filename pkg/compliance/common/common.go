// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/swhid"
	"github.com/interlynk-io/sbomqs/pkg/swid"
	"github.com/olekukonko/tablewriter"
	"github.com/samber/lo"
)

func CheckTools(tools []sbom.GetTool) (string, bool) {
	var result []string

	for _, tool := range tools {
		if name := tool.GetName(); name != "" {
			if version := tool.GetVersion(); version != "" {
				result = append(result, name+"-"+version)
			} else {
				result = append(result, name)
			}
		}
	}

	if len(result) == 0 {
		return "", false
	}

	return strings.Join(result, ", "), true
}

func CheckAuthors(authors []sbom.GetAuthor) (string, bool) {
	var result []string

	for _, author := range authors {
		if author.GetType() != "person" {
			continue
		}

		var parts []string
		name := author.GetName()
		email := author.GetEmail()
		phone := author.GetPhone()

		if name != "" {
			parts = append(parts, name)
		}

		var contactDetails []string
		if email != "" {
			contactDetails = append(contactDetails, email)
		}
		if phone != "" {
			contactDetails = append(contactDetails, phone)
		}

		if len(contactDetails) > 0 {
			parts = append(parts, "("+strings.Join(contactDetails, ", ")+")")
		}

		if len(parts) > 0 {
			result = append(result, strings.Join(parts, " "))
		}
	}

	if len(result) == 0 {
		return "", false
	}

	return strings.Join(result, ", "), true
}

func CheckSupplier(supplier sbom.GetSupplier) (string, bool) {
	var parts []string

	// Check for name and email
	if name := supplier.GetName(); name != "" {
		if email := supplier.GetEmail(); email != "" {
			parts = append(parts, name+", "+email)
		} else {
			parts = append(parts, name)
		}
	} else if email := supplier.GetEmail(); email != "" {
		parts = append(parts, email)
	}

	// Check for URL
	if url := supplier.GetURL(); url != "" {
		parts = append(parts, url)
	}

	// Check for contacts
	if contacts := supplier.GetContacts(); contacts != nil {
		var contactParts []string
		for _, contact := range contacts {
			if contactName := contact.GetName(); contactName != "" {
				if contactEmail := contact.GetEmail(); contactEmail != "" {
					contactParts = append(contactParts, contactName+", "+contactEmail)
				} else {
					contactParts = append(contactParts, contactName)
				}
			} else if contactEmail := contact.GetEmail(); contactEmail != "" {
				contactParts = append(contactParts, contactEmail)
			}
		}
		if len(contactParts) > 0 {
			parts = append(parts, "("+strings.Join(contactParts, ", ")+")")
		}
	}

	if len(parts) == 0 {
		return "", false
	}

	// Combine parts into the final string
	finalResult := strings.Join(parts, ", ")
	return finalResult, true
}

func CheckManufacturer(manufacturer sbom.GetManufacturer) (string, bool) {
	if email := manufacturer.GetEmail(); email != "" {
		return email, true
	}

	if url := manufacturer.GetURL(); url != "" {
		return url, true
	}

	if contacts := manufacturer.GetContacts(); contacts != nil {
		for _, contact := range contacts {
			if email := contact.GetEmail(); email != "" {
				return email, true
			}
		}
	}
	return "", false
}

func CheckTimestamp(timestamp string) (string, bool) {
	_, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return timestamp, false
	}
	return timestamp, true
}

func CheckPurls(purls []purl.PURL) (string, bool) {
	results := []string{}
	for _, p := range purls {
		if result := string(p); result != "" {
			results = append(results, result)
		}
	}
	if len(results) > 0 {
		return strings.Join(results, ", "), true
	}
	return "", false
}

func CheckCpes(cpes []cpe.CPE) (string, bool) {
	results := []string{}
	for _, c := range cpes {
		if result := string(c); result != "" {
			results = append(results, result)
		}
	}
	if len(results) > 0 {
		return strings.Join(results, ", "), true
	}
	return "", false
}

func CheckOmnibor(omni []omniborid.OMNIBORID) (string, bool) {
	results := []string{}
	for _, o := range omni {
		if result := string(o); result != "" {
			results = append(results, result)
		}
	}
	if len(results) > 0 {
		return strings.Join(results, ", "), true
	}
	return "", false
}

func CheckSwhid(swhid []swhid.SWHID) (string, bool) {
	results := []string{}
	for _, s := range swhid {
		if result := string(s); result != "" {
			results = append(results, result)
		}
	}
	if len(results) > 0 {
		return strings.Join(results, ", "), true
	}
	return "", false
}

func CheckSwid(swid []swid.SWID) (string, bool) {
	results := []string{}
	for _, s := range swid {
		if s.GetTagID() != "" && s.GetName() != "" {
			result := s.GetTagID() + ", " + s.GetName()
			results = append(results, result)
		}
	}
	if len(results) > 0 {
		return strings.Join(results, ", "), true
	}
	return "", false
}

func CheckHash(checksums []sbom.GetChecksum) (string, bool, bool) {
	lowerAlgos := []string{"SHA1", "SHA-1", "sha1", "sha-1", "MD5", "md5"}
	higherAlgos := []string{"SHA-512", "SHA256", "SHA-256", "sha256", "sha-256"}

	containLowerAlgo := lo.ContainsBy(checksums, func(checksum sbom.GetChecksum) bool {
		return lo.Contains(lowerAlgos, checksum.GetAlgo())
	})

	containHigherAlgo := lo.ContainsBy(checksums, func(checksum sbom.GetChecksum) bool {
		return lo.Contains(higherAlgos, checksum.GetAlgo())
	})

	var res []string
	for _, checksum := range checksums {
		if content := checksum.GetContent(); content != "" {
			res = append(res, checksum.GetAlgo())
		}
	}
	// results := ConvertMapToString(result)
	return strings.Join(res, ", "), containLowerAlgo, containHigherAlgo
}

// ConvertMapToString converts a map of type map[string]string into a string
// representation where each key-value pair is formatted as "key:value".
func ConvertMapToString(m map[string]string) string {
	var result []string

	for key, value := range m {
		result = append(result, key+": "+value)
	}

	return strings.Join(result, ", ")
}

func CheckCopyright(cp string) (string, bool) {
	if cp == "NOASSERTION" || cp == "NONE" {
		return "", false
	}
	return cp, true
}

// ComponentsLists return component lists as a map
func ComponentsLists(doc sbom.Document) map[string]bool {
	componentList := make(map[string]bool)
	for _, component := range doc.Components() {
		if doc.Spec().GetSpecType() == "spdx" {
			id := "SPDXRef-" + component.GetSpdxID()
			componentList[id] = true

		} else if doc.Spec().GetSpecType() == "cyclonedx" {
			componentList[component.GetID()] = true
		}
	}
	return componentList
}

// ComponentsNamesMapToIDs returns map of component ID as key and component Name as value
func ComponentsNamesMapToIDs(doc sbom.Document) map[string]string {
	compIDWithName := make(map[string]string)
	for _, component := range doc.Components() {
		if doc.Spec().GetSpecType() == "spdx" {
			id := "SPDXRef-" + component.GetSpdxID()
			compIDWithName[id] = component.GetName()

		} else if doc.Spec().GetSpecType() == "cyclonedx" {
			compIDWithName[component.GetID()] = component.GetName()
		}
	}
	return compIDWithName
}

// GetAllPrimaryComponentDependencies return all list of primary component dependencies by it's ID.
func GetAllPrimaryComponentDependencies(doc sbom.Document) []string {
	return doc.PrimaryComp().GetDependencies()
}

// MapPrimaryDependencies returns a map of all primary dependencies with bool.
// Primary dependencies marked as true else false.
func MapPrimaryDependencies(doc sbom.Document) map[string]bool {
	primaryDependencies := make(map[string]bool)
	for _, component := range doc.Components() {
		if doc.Spec().GetSpecType() == "spdx" {
			id := "SPDXRef-" + component.GetSpdxID()
			if component.GetPrimaryCompInfo().IsPresent() {
				dependencies := doc.GetRelationships(id)
				for _, d := range dependencies {
					primaryDependencies[d] = true
				}
			}
		} else if doc.Spec().GetSpecType() == "cyclonedx" {
			if component.GetPrimaryCompInfo().IsPresent() {
				dependencies := doc.GetRelationships(component.GetID())
				for _, d := range dependencies {
					primaryDependencies[d] = true
				}
			}
		}
	}
	return primaryDependencies
}

// CheckPrimaryDependenciesInComponentList checks if all primary dependencies are part of the component list.
func CheckPrimaryDependenciesInComponentList(dependencies []string, componentList map[string]bool) bool {
	return lo.EveryBy(dependencies, func(id string) bool {
		return componentList[id]
	})
}

// GetDependenciesByName returns the names of all dependencies based on their IDs.
func GetDependenciesByName(dependencies []string, compIDWithName map[string]string) []string {
	var allDepByName []string
	for _, dep := range dependencies {
		allDepByName = append(allDepByName, compIDWithName[dep])
	}
	return allDepByName
}

func GetID(componentID string) string {
	return "SPDXRef-" + componentID
}

func UniqueElementID(component sbom.GetComponent) string {
	componentName := path.Base(component.GetName())

	if len(componentName) > 20 {
		// "org.jetbrains.kotlin:kotlin-stdlib-jdk7" would become "org.jetbrain...lib-jdk7"
		componentName = componentName[:12] + "..." + componentName[len(componentName)-8:]
	}

	version := component.GetVersion()
	if len(version) > 12 {
		// "v0.0.0-20230321023759-10a507213a29" would become "v0.0.0...213a29"
		version = version[:6] + "..." + version[len(version)-6:]
	}

	return componentName + "-" + version
}

func IsComponentPartOfPrimaryDependency(primaryCompDeps []string, comp string) bool {
	for _, item := range primaryCompDeps {
		if item == comp {
			return true
		}
	}
	return false
}

func SetHeaderColor(table *tablewriter.Table, header int) {
	colors := make([]tablewriter.Colors, header)

	// each column with same color and style
	for i := 0; i < header; i++ {
		colors[i] = tablewriter.Colors{tablewriter.FgHiWhiteColor, tablewriter.Bold}
	}

	table.SetHeaderColor(colors...)
}

func ColorTable(table *tablewriter.Table, elementID, id string, elementResult string, dataFields string, score float64, columnWidth int) *tablewriter.Table {
	elementRe := wrapAndColoredContent(elementResult, columnWidth, tablewriter.FgHiCyanColor)
	dataField := wrapAndColoredContent(dataFields, columnWidth, tablewriter.FgHiBlueColor)

	scoreColor := GetScoreColor(score)

	table.Rich([]string{
		elementID,
		id,
		dataField,
		elementRe,
		fmt.Sprintf("%0.1f", score),
	}, []tablewriter.Colors{
		{tablewriter.FgHiMagentaColor, tablewriter.Bold},
		{tablewriter.FgHiCyanColor},
		{},
		{},
		scoreColor,
	})
	return table
}

// custom wrapping function to ensure consistent coloring instead of tablewritter's in-built wrapping
// 1. split content into multiple lines, each fitting within the specified width
// 2. each line of the content is formatted with color and bold styling using ANSI escape codes
// 3. wrapped lines are joined together with newline characters (\n) to maintain proper multi-line formatting.
func wrapAndColoredContent(content string, width int, color int) string {
	words := strings.Fields(content)
	var wrappedContent []string
	var currentLine string

	for _, word := range words {
		if len(currentLine)+len(word)+1 > width {

			// wrap the current line and color it
			wrappedContent = append(wrappedContent, fmt.Sprintf("\033[%d;%dm%s\033[0m", 1, color, currentLine))
			currentLine = word
		} else {
			if currentLine != "" {
				currentLine += " "
			}
			currentLine += word
		}
	}
	if currentLine != "" {
		wrappedContent = append(wrappedContent, fmt.Sprintf("\033[%d;%dm%s\033[0m", 1, color, currentLine))
	}

	return strings.Join(wrappedContent, "\n")
}

func GetScoreColor(score float64) tablewriter.Colors {
	if score == 0.0 {
		return tablewriter.Colors{tablewriter.FgRedColor, tablewriter.Bold}
	} else if score < 5.0 {
		return tablewriter.Colors{tablewriter.FgHiYellowColor, tablewriter.Bold}
	}
	return tablewriter.Colors{tablewriter.FgGreenColor, tablewriter.Bold}
}
