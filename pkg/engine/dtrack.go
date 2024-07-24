// Copyright 2023 Interlynk.io
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
	"strings"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/samber/lo"
)

type DtParams struct {
	URL        string
	APIKey     string
	ProjectIDs []uuid.UUID

	JSON     bool
	Basic    bool
	Detailed bool

	TagProjectWithScore bool
}

func DtrackScore(ctx context.Context, dtP *DtParams) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.DtrackScore()")

	log.Debugf("Config: %+v", dtP)

	dTrackClient, err := dtrack.NewClient(dtP.URL,
		dtrack.WithAPIKey(dtP.APIKey), dtrack.WithDebug(false))
	if err != nil {
		log.Fatalf("Failed to create Dependency-Track client: %s", err)
	}

	for _, pid := range dtP.ProjectIDs {
		log.Debugf("Processing project %s", pid)

		prj, err := dTrackClient.Project.Get(ctx, pid)
		if err != nil {
			log.Fatalf("Failed to get project: %s", err)
		}

		bom, err := dTrackClient.BOM.ExportProject(ctx, pid, dtrack.BOMFormatJSON, dtrack.BOMVariantInventory)
		if err != nil {
			log.Fatalf("Failed to export project: %s", err)
		}

		{
			fname := fmt.Sprintf("tmpfile-%s", pid)
			f, err := os.CreateTemp("", fname)
			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()
			defer os.Remove(f.Name())

			_, err = f.WriteString(bom)
			if err != nil {
				log.Fatalf("Failed to write string: %v", err)
			}

			ep := &Params{}
			ep.Path = append(ep.Path, f.Name())
			doc, scores, err := processFile(ctx, ep, ep.Path[0])
			if err != nil {
				return err
			}

			if dtP.TagProjectWithScore {
				log.Debugf("Project: %+v", prj.Tags)
				// remove old score
				prj.Tags = lo.Filter(prj.Tags, func(t dtrack.Tag, _ int) bool {
					return !strings.HasPrefix(t.Name, "sbomqs=")
				})

				tag := fmt.Sprintf("sbomqs=%0.1f", scores.AvgScore())
				prj.Tags = append(prj.Tags, dtrack.Tag{Name: tag})

				log.Debugf("Tagging project with %s", tag)
				log.Debugf("Project: %+v", prj.Tags)

				_, err = dTrackClient.Project.Update(ctx, prj)
				if err != nil {
					log.Fatalf("Failed to tag project: %s", err)
				}
			}

			path := fmt.Sprintf("ID: %s, Name: %s, Version: %s", prj.UUID, prj.Name, prj.Version)

			reportFormat := "detailed"
			if dtP.Basic {
				reportFormat = "basic"
			} else if dtP.JSON {
				reportFormat = "json"
			}

			nr := reporter.NewReport(ctx,
				[]sbom.Document{doc},
				[]scorer.Scores{scores},
				[]string{path},
				reporter.WithFormat(reportFormat))
			nr.Report()
		}
	}

	return nil
}
