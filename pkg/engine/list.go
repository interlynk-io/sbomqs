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
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/list"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func ListRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ListRun()")

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	path := ep.Path[0]

	if _, err := os.Stat(path); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", path)
		fmt.Printf("failed to stat %s\n", path)
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", path)
		fmt.Printf("failed to open %s\n", path)
		return err
	}
	defer f.Close()

	// parse SBOM file into SBOM document
	doc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		log.Debugf("failed to create sbom document for  SBOM file path:%s\n", path)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse sbom document from SBOM file path %s: %s\n", path, err)
		return err
	}

	listParams := list.ListParams{
		Path:     ep.Path,
		Features: ep.Features,
		JSON:     ep.JSON,
		Basic:    ep.Basic,
		Detailed: ep.Detailed,
		Color:    ep.Color,
		Missing:  ep.Missing,
		Debug:    ep.Debug,
	}
	_, err = list.ComponentsListResult(ctx, listParams, doc)
	if err != nil {
		log.Debugf("ListComponents failed for SBOM document :%s\n", ep.Path[0])
		fmt.Printf("failed to list components for SBOM document :%s\n", ep.Path[0])
		return err
	}

	return nil
}
