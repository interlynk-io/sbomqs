// Copyright 2025 Interlynk.io
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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/swhid"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
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
	result := make([]string, 0, len(m))

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
	allDepByName := make([]string, 0, len(dependencies))
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

func WrapText(input string, maxWidth int) string {
	var result []string
	for len(input) > maxWidth {
		splitPoint := strings.LastIndex(input[:maxWidth], "/")
		if splitPoint == -1 {
			splitPoint = maxWidth
		}
		result = append(result, input[:splitPoint])
		input = input[splitPoint:]
	}
	result = append(result, input)
	return strings.Join(result, "\n")
}

// convert long text into multiple lines
func WrapLongTextIntoMulti(input string, maxWidth int) string {
	var result []string
	for len(input) > maxWidth {
		result = append(result, input[:maxWidth])
		input = input[maxWidth:]
	}
	result = append(result, input)
	return strings.Join(result, "\n")
}

func AreLicensesValid(licenses []licenses.License) bool {
	if len(licenses) == 0 {
		return false
	}
	var spdx, aboutcode, custom int

	for _, license := range licenses {
		switch license.Source() {
		case "spdx":
			spdx++
		case "aboutcode":
			aboutcode++
		case "custom":
			if strings.HasPrefix(license.ShortID(), "LicenseRef-") || strings.HasPrefix(license.Name(), "LicenseRef-") {
				custom++
			}
		}
	}

	return spdx+aboutcode+custom == len(licenses)
}

func VerifySignature(pubKeyData []byte, sbomPath, signaturePath string) (bool, error) {
	block, _ := pem.Decode(pubKeyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return false, fmt.Errorf("invalid public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("not an RSA public key")
	}

	// Hash the SBOM
	hash, err := HashSBOM(sbomPath)
	if err != nil {
		return false, err
	}

	// Load and decode the signature
	// #nosec G304 -- User-provided paths are expected for CLI tool
	sig, err := os.ReadFile(signaturePath)
	if err != nil {
		return false, err
	}

	// Verify the signature
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hash, sig)
	if err != nil {
		return false, err
	}

	return true, err
}

func HashSBOM(sbomPath string) ([]byte, error) {
	// #nosec G304 -- User-provided paths are expected for CLI tool
	sbomData, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(sbomData)
	return hash[:], nil
}

func RemoveFileIfExists(filePath string) {
	if _, err := os.Stat(filePath); err == nil {
		err = os.Remove(filePath)
		if err != nil {
			fmt.Printf("Failed to delete file %s: %v\n", filePath, err)
		}
	} else if !os.IsNotExist(err) {
		fmt.Printf("Error checking file %s: %v\n", filePath, err)
	}
}
