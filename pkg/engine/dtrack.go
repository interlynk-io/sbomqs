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
	"strings"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/reporter"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer"
	"github.com/samber/lo"
)

type DtParams struct {
	URL        string
	APIKey     string
	ProjectIDs []uuid.UUID

	JSON     bool
	Basic    bool
	Detailed bool

	Legacy  bool
	Profile []string

	TagProjectWithScore bool
	TagProjectWithGrade bool
	Timeout             int // handle cutom timeout
}

func DtrackScore(ctx context.Context, dtP *DtParams) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.DtrackScore()")

	log.Debugf("Config: %+v", dtP)

	timeout := time.Duration(dtP.Timeout) * time.Second

	log.Debug("Timeout set to: ", timeout)

	dTrackClient, err := dtrack.NewClient(dtP.URL,
		dtrack.WithAPIKey(dtP.APIKey), dtrack.WithTimeout(timeout), dtrack.WithDebug(false))
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

			defer func() {
				if err := f.Close(); err != nil {
					log.Warnf("failed to close file: %v", err)
				}
			}()
			defer func() {
				if err := os.Remove(f.Name()); err != nil {
					log.Warnf("failed to remove temporary file: %v", err)
				}
			}()

			_, err = f.WriteString(bom)
			if err != nil {
				log.Fatalf("Failed to write string: %v", err)
			}

			ep := &Params{
				Basic:    dtP.Basic,
				JSON:     dtP.JSON,
				Detailed: dtP.Detailed,
				Profiles: dtP.Profile,
			}

			ep.Path = append(ep.Path, f.Name())

			if dtP.Legacy {
				doc, scores, err := processFile(ctx, ep, ep.Path[0], nil)
				if err != nil {
					return err
				}

				if dtP.TagProjectWithScore {
					tagProjectWithScore(ctx, dTrackClient, prj, scores.AvgScore())
				}

				path := fmt.Sprintf("ID: %s, Name: %s, Version: %s", prj.UUID, prj.Name, prj.Version)

				reportFormat := common.ReportDetailed
				if dtP.Basic {
					reportFormat = common.ReportBasic
				} else if dtP.JSON {
					reportFormat = common.FormatJSON
				}

				nr := reporter.NewReport(ctx,
					[]sbom.Document{doc},
					[]scorer.Scores{scores},
					[]string{path},
					reporter.WithFormat(reportFormat))
				nr.Report()

			} else {

				results, err := scored(ctx, ep)
				if err != nil {
					return err
				}

				if dtP.TagProjectWithScore || dtP.TagProjectWithGrade {
					log.Debugf("Project: %+v", prj.Tags)

					profileKeys := dtP.Profile
					if len(profileKeys) == 0 {
						profileKeys = []string{""}
					}

					prefixes := lo.Uniq(lo.Map(profileKeys, func(p string, _ int) string {
						return profileTagPrefix(p)
					}))

					// Remove old score/grade tags only for those prefixes.
					prj.Tags = lo.Filter(prj.Tags, func(t dtrack.Tag, _ int) bool {
						for _, prefix := range prefixes {
							if dtP.TagProjectWithScore && strings.HasPrefix(t.Name, prefix+"=") {
								return false
							}
							if dtP.TagProjectWithGrade && strings.HasPrefix(t.Name, prefix+"-grade=") {
								return false
							}
						}
						return true
					})

					// var interlynkScore float64
					// var grade string

					for _, r := range results {
						// Case 1: comprehensive (Interlynk) is present
						if r.Comprehensive != nil {
							prefix := profileTagPrefix("sbomqs")
							score := r.Comprehensive.InterlynkScore
							grade := r.Comprehensive.Grade

							if dtP.TagProjectWithScore {
								scoreTag := fmt.Sprintf("%s=%0.1f", prefix, score)
								prj.Tags = append(prj.Tags, dtrack.Tag{Name: scoreTag})
								log.Debugf("Tagging project with %s", scoreTag)
							}
							if dtP.TagProjectWithGrade {
								gradeTag := fmt.Sprintf("%s-grade=%s", prefix, grade)
								prj.Tags = append(prj.Tags, dtrack.Tag{Name: gradeTag})
								log.Debugf("Tagging project with %s", gradeTag)
							}
						}

						// Case 2: profile-based scoring
						if r.Profiles != nil {
							// NOTE: assuming ProfResult entries correspond to requested profiles.
							for _, proResult := range r.Profiles.ProfResult {
								// You may have proResult.Key or ID;
								// if not, wire this to your profile identifier.
								profileKey := strings.ToLower(proResult.Key) // or proResult.ID / Name mapping
								prefix := profileTagPrefix(profileKey)

								if dtP.TagProjectWithScore {
									scoreTag := fmt.Sprintf("%s=%0.1f", prefix, proResult.Score)
									prj.Tags = append(prj.Tags, dtrack.Tag{Name: scoreTag})
									log.Debugf("Tagging project with %s", scoreTag)
								}
								if dtP.TagProjectWithGrade {
									gradeTag := fmt.Sprintf("%s-grade=%s", prefix, proResult.Grade)
									prj.Tags = append(prj.Tags, dtrack.Tag{Name: gradeTag})
									log.Debugf("Tagging project with %s", gradeTag)
								}
							}
						}
					}

					log.Debugf("Project (after tagging): %+v", prj.Tags)

					// if dtP.TagProjectWithScore {
					// 	scoreTag := fmt.Sprintf("sbomqs=%0.1f", interlynkScore)
					// 	prj.Tags = append(prj.Tags, dtrack.Tag{Name: scoreTag})
					// 	log.Debugf("Tagging project with %s", scoreTag)
					// }

					// if dtP.TagProjectWithGrade {
					// 	gradeTag := fmt.Sprintf("sbomqs-grade=%s", grade)
					// 	prj.Tags = append(prj.Tags, dtrack.Tag{Name: gradeTag})
					// 	log.Debugf("Tagging project with %s", gradeTag)
					// }

					// log.Debugf("Project: %+v", prj.Tags)

					_, err = dTrackClient.Project.Update(ctx, prj)
					if err != nil {
						log.Fatalf("Failed to tag project: %s", err)
					}
				}

				renderReport(ctx, ep, results)
				return nil
			}
		}
	}

	return nil
}

// profileTagPrefix returns the tag prefix for a given profile key.
// By default, for interlynk (or empty) we keep "sbomqs" for backward compatibility,
// and for other profiles we use the profile string itself (e.g. "ntia", "bsi-v2.0").
func profileTagPrefix(profile string) string {
	p := strings.TrimSpace(strings.ToLower(profile))
	if p == "" || p == "interlynk" {
		return "sbomqs"
	}
	return p
}

func tagProjectWithScore(ctx context.Context, dTrackClient *dtrack.Client, prj dtrack.Project, finalScore float64) {
	log := logger.FromContext(ctx)

	log.Debugf("Project: %+v", prj.Tags)
	// remove old score
	prj.Tags = lo.Filter(prj.Tags, func(t dtrack.Tag, _ int) bool {
		return !strings.HasPrefix(t.Name, "sbomqs=")
	})

	tag := fmt.Sprintf("sbomqs=%0.1f", finalScore)
	prj.Tags = append(prj.Tags, dtrack.Tag{Name: tag})

	log.Debugf("Tagging project with %s", tag)
	log.Debugf("Project: %+v", prj.Tags)

	_, err := dTrackClient.Project.Update(ctx, prj)
	if err != nil {
		log.Fatalf("Failed to tag project: %s", err)
	}
}
