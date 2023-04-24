// Copyright 2023 Interlynk.io
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

package scorer

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

func DefaultConfig() string {
	d, err := yaml.Marshal(checks)
	if err != nil {
		log.Fatal(err)
	}

	return string(d)
}

func ReadConfigFile(path string) ([]Filter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cks []check
	err = yaml.NewDecoder(f).Decode(&cks)
	if err != nil {
		return nil, err
	}

	filters := []Filter{}
	for _, ck := range cks {
		if ck.Ignore {
			filters = append(filters, Filter{ck.Key, Feature})
		}
	}

	return filters, nil
}
