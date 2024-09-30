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
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/swhid"
	"github.com/interlynk-io/sbomqs/pkg/swid"
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

func CheckManufacturer(manufacturer sbom.Manufacturer) (string, bool) {
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
	return cp, cp != "NOASSERTION" && cp != "NONE"
}
