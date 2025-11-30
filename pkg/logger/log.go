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

// Package logger provides structured logging capabilities for the sbomqs application
// using the Uber Zap logger library with context-aware logging support.
package logger

import (
	"context"
	"log"

	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

type logKey struct{}

// InitProdLogger initializes a production-ready logger with JSON formatting
// and appropriate log levels for production environments.
func InitProdLogger() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	defer func() {
		if err := logger.Sync(); err != nil {
			return
		}
	}()

	if logger != nil {
		panic("logger already initialized")
	}
	logger = l.Sugar()
}

// InitDebugLogger initializes a development logger with console formatting
// and debug-level logging for development and testing environments.
func InitDebugLogger() {
	l, err := zap.NewDevelopment()
	if err != nil {
		log.Printf("Failed to zap new development: %v", err)
	}

	defer func() {
		if err := logger.Sync(); err != nil {
			return
		}
	}()

	if logger != nil {
		panic("logger already initialized")
	}
	logger = l.Sugar()
}

// WithLogger returns a new context with the logger attached.
// This enables context-aware logging throughout the application.
func WithLogger(ctx context.Context) context.Context {
	return context.WithValue(ctx, logKey{}, logger)
}

func WithLoggerAndCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.WithValue(ctx, logKey{}, logger))
}

// FromContext retrieves a logger from the provided context.
// Returns a no-op logger if no logger is found in the context.
func FromContext(ctx context.Context) *zap.SugaredLogger {
	if logger, ok := ctx.Value(logKey{}).(*zap.SugaredLogger); ok {
		return logger
	}

	return zap.NewNop().Sugar()
}
