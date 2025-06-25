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

package logger

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

type contextKey struct{}

func InitProdLogger() error {
	if logger != nil {
		logger.Warn("logger already initialized, skipping reinitialization")
		return nil
	}

	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	l, err := config.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize production logger: %w", err)
	}
	defer l.Sync()

	logger = l.Sugar()
	logger.Info("Production logger initialized")
	return nil
}

func InitDebugLogger() {
	if logger != nil {
		panic("logger already initialized")
	}

	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	l, err := config.Build()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	logger = l.Sugar()
}

// func WithLoggerAndCancel(ctx context.Context) (context.Context, context.CancelFunc) {
// 	return context.WithCancel(context.WithValue(ctx, logKey{}, logger))
// }

func WithLogger(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	if l, ok := ctx.Value(contextKey{}).(*zap.SugaredLogger); ok {
		return l
	}
	return zap.NewNop().Sugar()
}

// DeinitLogger deinitializes the logger by syncing and resetting it.
func DeinitLogger() {
	if logger != nil {
		_ = logger.Sync()
		logger = nil
	}
}

func Sync() {
	if logger != nil {
		_ = logger.Sync()
	}
}

// LogError logs an error message with optional key-value pairs for structured logging.
func LogError(ctx context.Context, err error, msg string, keysAndValues ...interface{}) {
	logger := FromContext(ctx)
	if err != nil {
		keysAndValues = append(keysAndValues, "error", err)
	}
	logger.Errorw(msg, keysAndValues...)
}

// LogDebug logs debug messages if debug mode is enabled.
func LogDebug(ctx context.Context, msg string, keysAndValues ...interface{}) {
	FromContext(ctx).Debugw(msg, keysAndValues...)
}

// LogInfo logs informational messages.
func LogInfo(ctx context.Context, msg string, keysAndValues ...interface{}) {
	FromContext(ctx).Infow(msg, keysAndValues...)
}
