// Copyright 2025 Interlynk.io
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

package policy

import "io"

// ReportJSON writes results as JSON.
func ReportJSON(w io.Writer, results []Result) error {
	// TODO: implement JSON reporting
	return nil
}

// ReportYAML writes results as YAML.
func ReportYAML(w io.Writer, results []Result) error {
	// TODO: implement YAML reporting
	return nil
}

// ReportTable writes results in a table format.
func ReportTable(w io.Writer, results []Result) error {
	// TODO: implement table reporting
	return nil
}
