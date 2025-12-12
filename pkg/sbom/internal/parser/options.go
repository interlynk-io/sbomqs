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

import "context"

// Config holds common configuration for document parsing
type Config struct {
	Context          context.Context
	SkipValidation   bool
	StrictMode       bool
	CollectWarnings  bool
	Logger           *LogCollector
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Context:         context.Background(),
		SkipValidation:  false,
		StrictMode:      false,
		CollectWarnings: true,
		Logger:          NewLogCollector(),
	}
}

// Option is a functional option for configuration
type Option interface {
	Apply(*Config)
}

// optionFunc is a function that implements Option
type optionFunc func(*Config)

// Apply applies the option to the config
func (f optionFunc) Apply(c *Config) {
	f(c)
}

// WithContext sets the context for parsing
func WithContext(ctx context.Context) Option {
	return optionFunc(func(c *Config) {
		c.Context = ctx
	})
}

// WithoutValidation disables schema validation
func WithoutValidation() Option {
	return optionFunc(func(c *Config) {
		c.SkipValidation = true
	})
}

// WithStrictMode enables strict parsing mode
func WithStrictMode() Option {
	return optionFunc(func(c *Config) {
		c.StrictMode = true
	})
}

// WithWarnings enables warning collection
func WithWarnings(collect bool) Option {
	return optionFunc(func(c *Config) {
		c.CollectWarnings = collect
	})
}

// WithLogger sets a custom logger
func WithLogger(logger *LogCollector) Option {
	return optionFunc(func(c *Config) {
		c.Logger = logger
	})
}