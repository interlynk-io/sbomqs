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

package compliance

type record struct {
	check_key   int
	check_value string
	id          string
	score       float64
	required    bool
}

func newRecord() *record {
	return &record{}
}

func newRecordStmt(key int, id, value string, score float64) *record {
	r := newRecord()
	r.check_key = key
	r.check_value = value
	r.id = id
	r.score = score
	r.required = true
	return r
}

func newRecordStmtOptional(key int, id, value string, score float64) *record {
	r := newRecord()
	r.check_key = key
	r.check_value = value
	r.id = id
	r.score = score
	r.required = false
	return r
}
