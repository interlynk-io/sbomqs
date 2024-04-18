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

package engine

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/compliance"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func ComplianceRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ComplianceRun()")

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	log.Debugf("Config: %+v", ep)

	doc, error := getSbomDocument(ctx, ep)

	if error != nil {
		log.Debugf("getSbomDocument failed for file :%s\n", ep.Path[0])
		fmt.Printf("failed to get sbom document for %s\n", ep.Path[0])
		return error
	}

	reportType := "NTIA"

	if ep.Cra {
		reportType = "CRA"
	}

	outFormat := "json"

	if ep.Basic {
		outFormat = "basic"
	} else if ep.Pdf {
		outFormat = "pdf"
	}

	err := compliance.ComplianceResult(ctx, *doc, reportType, ep.Path[0], outFormat)
	if err != nil {
		log.Debugf("compliance.ComplianceResult failed for file :%s\n", ep.Path[0])
		fmt.Printf("failed to get compliance result for %s\n", ep.Path[0])
		return err
	}

	log.Debugf("Compliance Report: %s\n", ep.Path[0])
	return nil
}

func getSbomDocument(ctx context.Context, ep *Params) (*sbom.Document, error) {
	log := logger.FromContext(ctx)
	log.Debugf("engine.getSbomDocument()")

	path := ep.Path[0]

	if _, err := os.Stat(path); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", path)
		fmt.Printf("failed to stat %s\n", path)
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", path)
		fmt.Printf("failed to open %s\n", path)
		return nil, err
	}
	defer f.Close()

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", path)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s : %s\n", path, err)
		return nil, err
	}

	return &doc, nil
}
