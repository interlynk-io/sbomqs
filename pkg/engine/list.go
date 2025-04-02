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
	path := ep.Path[0]

	log := logger.FromContext(ctx)
	log.Debug("engine.ListRun()")

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	log.Debugf("Config: %+v", ep)

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

	doc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", path)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s : %s\n", path, err)
		return err
	}

	result, err := list.ComponentsListResult(ctx, ep.Features, doc, path, ep.Missing)
	if err != nil {
		log.Debugf("ListComponents failed for file :%s\n", ep.Path[0])
		fmt.Printf("failed to list components for %s\n", ep.Path[0])
		return err
	}

	fmt.Println("Components: ", result.Components)
	return nil
}
