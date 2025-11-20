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

package engine

import (
	"context"

	"github.com/interlynk-io/sbomqs/v2/pkg/list"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
)

func parseListParams(ep *Params) *list.Params {
	return &list.Params{
		Path:     ep.Path,
		Features: ep.Features,
		JSON:     ep.JSON,
		Basic:    ep.Basic,
		Detailed: ep.Detailed,
		Color:    ep.Color,
		Missing:  ep.Missing,
		Debug:    ep.Debug,
		Show:     ep.Show,
	}
}

func ListRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ListRun()")

	lep := parseListParams(ep)

	// Process the SBOMs and features
	_, err := list.ComponentsListResult(ctx, lep)
	if err != nil {
		log.Debugf("failed to process SBOMs: %v", err)
		return err
	}

	return nil
}
