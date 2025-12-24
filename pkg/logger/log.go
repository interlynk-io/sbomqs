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
	"go.uber.org/zap/zapcore"
)

type contextKey struct{}

var logger *zap.Logger

func Init(debug bool) {
	if logger != nil {
		panic("logger already initialized")
	}

	level := zapcore.ErrorLevel
	if debug {
		level = zapcore.DebugLevel
	}

	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(level),
		Development: debug,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:      "time",
			LevelKey:     "level",
			MessageKey:   "msg",
			CallerKey:    "caller",
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			EncodeLevel:  zapcore.CapitalColorLevelEncoder,
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	l, err := cfg.Build(zap.AddCaller())
	if err != nil {
		panic(err)
	}

	logger = l
}

func DeinitLogger() {
	if logger != nil {
		_ = logger.Sync()
		logger = nil
	}
}

// WithLogger attaches logger to context.
func WithLogger(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// FromContext retrieves logger from context.
func FromContext(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(contextKey{}).(*zap.Logger); ok && l != nil {
		return l
	}
	return zap.NewNop()
}

// Sync flushes buffered logs.
func Sync() {
	if logger != nil {
		if err := logger.Sync(); err != nil {
			log.Printf("logger sync failed: %v", err)
		}
	}
}
