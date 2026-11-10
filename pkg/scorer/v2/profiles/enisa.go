// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package profiles

import (

	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
)

// ENISASBOMAuthors checks whether the SBOM has at least one Person-type author.
// ENISA defines SBOM Author as a person — Organization represents supplier/producer,
// and Tool entries are captured separately under Tool Name.
func ENISASBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	if common.IsSBOMAuthorPerson(doc) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "SBOM author (person) is declared",
			Ignore: false,
		}
	}

	// Check if there are Organization or Tool entries to provide helpful message
	authors := doc.Authors()
	for _, author := range authors {
		if strings.EqualFold(author.GetType(), "organization") {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Organization found but ENISA requires Person as author; use Supplier/Producer fields for organizations",
				Ignore: false,
			}
		}
		if strings.EqualFold(author.GetType(), "tool") {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Tool found but ENISA requires Person as author; tool entries are captured separately",
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM author (person) is missing",
		Ignore: false,
	}
}

// ENISACompProducer checks whether each component has a Person-type producer.
// ENISA defines Software Producer as the individual/role that created the component,
// not the organization that distributes it. Organization entries are rejected.
func ENISACompProducer(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := 0
	for _, c := range comps {
		for _, author := range c.Authors() {
			if strings.EqualFold(author.GetType(), "person") {
				if strings.TrimSpace(author.GetName()) != "" || strings.TrimSpace(author.GetEmail()) != "" {
					valid++
					break
				}
			}
		}
	}
	return ntia2026ComponentScore(valid, len(comps), "producer")
}
