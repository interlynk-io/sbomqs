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

import (
	"fmt"
	"regexp"
	"strings"
)

func parseRuleString(s string) (Rule, error) {
	// split by comma but allow simple values; we assume callers don't include escaped commas
	parts := strings.Split(s, ",")
	kv := map[string]string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "=") {
			return Rule{}, fmt.Errorf("invalid key=value segment: %q", part)
		}
		kvs := strings.SplitN(part, "=", 2)
		k := strings.TrimSpace(kvs[0])
		v := strings.TrimSpace(kvs[1])
		kv[k] = v
	}
	field, ok := kv["field"]
	if !ok || field == "" {
		return Rule{}, fmt.Errorf("field is required in rule")
	}
	r := Rule{Field: field}
	if vals, ok := kv["values"]; ok && vals != "" {
		// split on commas
		r.Values = splitCommaList(vals)
	}
	if pats, ok := kv["patterns"]; ok && pats != "" {
		r.Patterns = splitCommaList(pats)
		// validate regex
		for _, p := range r.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				return Rule{}, fmt.Errorf("invalid pattern %q: %w", p, err)
			}
		}
	}
	return r, nil
}

func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
