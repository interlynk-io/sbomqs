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

package parser

import (
	"fmt"
	"regexp"
	"strings"
)

// Entity represents a parsed entity with name and email
type Entity struct {
	Name  string
	Email string
}

// ParseEntity parses an entity string in the format "Type: Name (email)"
func ParseEntity(in string) *Entity {
	if strings.HasPrefix(in, ":") {
		in = strings.TrimSpace(strings.TrimLeft(in, ":"))
	}

	if strings.ToUpper(in) == "NOASSERTION" || strings.ToUpper(in) == "NONE" {
		return &Entity{Name: in}
	}

	// Regex pattern to match organization or person and email
	pattern := `(Organization|Person)\s*:\s*([^(]+)\s*(?:\(?\s*([^)]+)\s*\)?)?`
	regex := regexp.MustCompile(pattern)
	match := regex.FindStringSubmatch(in)

	if len(match) == 0 {
		return nil
	}

	name := strings.TrimSpace(match[2])
	var email string
	if len(match) > 3 {
		email = strings.TrimSpace(match[3])
	}

	return &Entity{Name: name, Email: email}
}

// CleanKey removes quotes from a key string
func CleanKey(key string) string {
	return strings.Trim(key, `"`)
}

// ErrorContext wraps an error with additional context
type ErrorContext struct {
	Component string
	Index     int
	Field     string
	Message   string
}

// WrapError creates a formatted error with context
func WrapError(err error, ctx ErrorContext) error {
	if err == nil {
		return nil
	}
	
	var parts []string
	if ctx.Component != "" {
		parts = append(parts, fmt.Sprintf("component %s", ctx.Component))
	}
	if ctx.Index >= 0 {
		parts = append(parts, fmt.Sprintf("index %d", ctx.Index))
	}
	if ctx.Field != "" {
		parts = append(parts, fmt.Sprintf("field %s", ctx.Field))
	}
	if ctx.Message != "" {
		parts = append(parts, ctx.Message)
	}
	
	if len(parts) > 0 {
		return fmt.Errorf("%s: %w", strings.Join(parts, ", "), err)
	}
	return err
}

// LogCollector collects parsing logs
type LogCollector struct {
	logs []string
}

// NewLogCollector creates a new log collector
func NewLogCollector() *LogCollector {
	return &LogCollector{
		logs: make([]string, 0),
	}
}

// Add adds a log message
func (l *LogCollector) Add(format string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf(format, args...))
}

// Logs returns all collected logs
func (l *LogCollector) Logs() []string {
	return l.logs
}

// Clear clears all logs
func (l *LogCollector) Clear() {
	l.logs = l.logs[:0]
}