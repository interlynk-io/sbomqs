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
	"go.uber.org/zap"
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
	log.Info("Starting Dependency-Track scoring run",
		zap.String("dtrack_url", dtP.URL),
		zap.Int("project_count", len(dtP.ProjectIDs)),
	)

	log.Debug("DTrack scoring configuration",
		zap.Bool("legacy", dtP.Legacy),
		zap.Bool("basic", dtP.Basic),
		zap.Bool("json", dtP.JSON),
		zap.Bool("detailed", dtP.Detailed),
		zap.Bool("tag_score", dtP.TagProjectWithScore),
		zap.Bool("tag_grade", dtP.TagProjectWithGrade),
		zap.Int("timeout_seconds", dtP.Timeout),
		zap.Strings("profiles", dtP.Profile),
	)

	timeout := time.Duration(dtP.Timeout) * time.Second

	log.Info("Creating Dependency-Track client",
		zap.String("url", dtP.URL),
		zap.Duration("timeout", timeout),
	)

	dTrackClient, err := dtrack.NewClient(dtP.URL,
		dtrack.WithAPIKey(dtP.APIKey), dtrack.WithTimeout(timeout), dtrack.WithDebug(false))
	if err != nil {
		log.Error("Failed to create Dependency-Track client",
			zap.String("url", dtP.URL),
			zap.Error(err),
		)
		return err
	}

	for _, pid := range dtP.ProjectIDs {
		log.Info("Processing Dependency-Track project",
			zap.String("project_id", pid.String()),
		)

		log.Debug("Fetching project metadata",
			zap.String("project_id", pid.String()),
		)

		prj, err := dTrackClient.Project.Get(ctx, pid)
		if err != nil {
			log.Error("Failed to fetch project",
				zap.String("project_id", pid.String()),
				zap.Error(err),
			)
			return err
		}

		log.Debug("Project resolved",
			zap.String("project_id", prj.UUID.String()),
			zap.String("name", prj.Name),
			zap.String("version", prj.Version),
		)

		log.Info("Exporting project BOM",
			zap.String("project_id", pid.String()),
		)

		bom, err := dTrackClient.BOM.ExportProject(ctx, pid, dtrack.BOMFormatJSON, dtrack.BOMVariantInventory)
		if err != nil {
			log.Error("Failed to export project BOM",
				zap.String("project_id", pid.String()),
				zap.Error(err),
			)
			return err
		}

		{
			log.Debug("Creating temporary BOM file",
				zap.String("project_id", pid.String()),
			)

			fname := fmt.Sprintf("tmpfile-%s", pid)
			f, err := os.CreateTemp("", fname)
			if err != nil {
				log.Error("failed to create file", zap.String("name", fname), zap.Error(err))
				return err
			}

			defer func() {
				if err := f.Close(); err != nil {
					log.Warn("failed to close file", zap.Error(err))
				}
			}()
			defer func() {
				if err := os.Remove(f.Name()); err != nil {
					log.Warn("Failed to clean up temporary file",
						zap.String("file", f.Name()),
						zap.Error(err),
					)
				}
			}()

			_, err = f.WriteString(bom)
			if err != nil {
				log.Error("Failed to write SBOM", zap.String("file", fname), zap.Error(err))
				return err
			}

			ep := &Params{
				Basic:    dtP.Basic,
				JSON:     dtP.JSON,
				Detailed: dtP.Detailed,
				Profiles: dtP.Profile,
			}

			ep.Path = append(ep.Path, f.Name())
			log.Debug("New configuration constructed",
				zap.Bool("basic", ep.Basic),
				zap.Bool("json", ep.JSON),
				zap.Bool("detailed", ep.Detailed),
				zap.Strings("profiles", ep.Profiles),
				zap.Strings("paths", ep.Path),
			)

			log.Debug("Scoring mode selected",
				zap.Bool("legacy", dtP.Legacy),
			)

			if dtP.Legacy {
				log.Info("Running legacy scoring",
					zap.String("project_id", pid.String()),
				)

				log.Debug("Processing scores and parsing SBOM document",
					zap.String("path", ep.Path[0]),
				)

				doc, scores, err := processFile(ctx, ep, ep.Path[0], nil)
				if err != nil {
					return err
				}

				if dtP.TagProjectWithScore {
					log.Info("Tagging project with average score",
						zap.String("project_id", prj.UUID.String()),
						zap.Float64("avg_score", scores.AvgScore()),
					)
					tagProjectWithScore(ctx, dTrackClient, prj, scores.AvgScore())
				}

				path := fmt.Sprintf("ID: %s, Name: %s, Version: %s", prj.UUID, prj.Name, prj.Version)

				reportFormat := common.ReportDetailed
				if dtP.Basic {
					reportFormat = common.ReportBasic
				} else if dtP.JSON {
					reportFormat = common.FormatJSON
				}

				log.Debug("Generating report for SBOM document",
					zap.String("path", path),
				)

				nr := reporter.NewReport(ctx,
					[]sbom.Document{doc},
					[]scorer.Scores{scores},
					[]string{path},
					reporter.WithFormat(reportFormat))
				nr.Report()

				log.Debug("Report generated",
					zap.String("path", path),
				)

			} else {

				log.Info("Running comprehenssive-based scoring",
					zap.String("project_id", prj.UUID.String()),
					zap.Strings("profiles", dtP.Profile),
				)

				log.Debug("Running SBOM scoring",
					zap.Strings("paths", ep.Path),
				)

				results, err := scored(ctx, ep)
				if err != nil {
					return err
				}

				if dtP.TagProjectWithScore || dtP.TagProjectWithGrade {

					log.Info("Tagging project with average score or grade",
						zap.String("project_id", prj.UUID.String()),
					)

					var prefixes []string
					profileKeys := dtP.Profile
					if len(profileKeys) > 0 {
						prefixes = lo.Uniq(lo.Map(profileKeys, func(p string, _ int) string {
							return profileTagPrefix(p)
						}))
					}

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

					for _, r := range results {
						// Case 1: comprehensive (Interlynk) is present
						if r.Comprehensive != nil {

							prefix := profileTagPrefix("interlynk")
							score := r.Comprehensive.InterlynkScore
							grade := r.Comprehensive.Grade

							log.Debug("Comprehenssive scoring result",
								zap.Float64("score", score),
								zap.String("grade", grade),
							)

							if dtP.TagProjectWithScore {
								scoreTag := fmt.Sprintf("%s=%0.1f", prefix, score)
								prj.Tags = append(prj.Tags, dtrack.Tag{Name: scoreTag})
								log.Debug("Tagging D-Track project with Interlynk score",
									zap.String("tag", scoreTag),
								)
							}

							if dtP.TagProjectWithGrade {
								gradeTag := fmt.Sprintf("%s-grade=%s", prefix, grade)
								prj.Tags = append(prj.Tags, dtrack.Tag{Name: gradeTag})
								log.Debug("Tagging D-Track project with Interlynk rade",
									zap.String("tag", gradeTag),
								)
							}
						}

						// Case 2: profile-based scoring
						if r.Profiles != nil && len(profileKeys) > 0 {
							for _, proResult := range r.Profiles.ProfResult {
								profileKey := strings.ToLower(proResult.Key)
								prefix := profileTagPrefix(profileKey)

								log.Debug("Profile-Based scoring result",
									zap.Float64("score", proResult.Score),
									zap.String("grade", proResult.Grade),
								)

								if dtP.TagProjectWithScore {
									scoreTag := fmt.Sprintf("%s=%0.1f", prefix, proResult.Score)
									prj.Tags = append(prj.Tags, dtrack.Tag{Name: scoreTag})
									log.Debug("Tagging D-Track project with Profile score",
										zap.String("tag", scoreTag),
									)
								}

								if dtP.TagProjectWithGrade {
									gradeTag := fmt.Sprintf("%s-grade=%s", prefix, proResult.Grade)
									prj.Tags = append(prj.Tags, dtrack.Tag{Name: gradeTag})
									log.Debug("Tagging D-Track project with Profile grade",
										zap.String("tag", gradeTag),
									)
								}
							}
						}
					}

					log.Info("Updating project tags in Dependency-Track",
						zap.String("project_id", prj.UUID.String()),
						zap.Int("tag_count", len(prj.Tags)),
					)

					_, err = dTrackClient.Project.Update(ctx, prj)
					if err != nil {
						log.Error("Failed to update project tags",
							zap.String("project_id", prj.UUID.String()),
							zap.Error(err),
						)
						return err
					}
				}

				log.Info("Rendering scoring report",
					zap.String("project_id", prj.UUID.String()),
				)
				renderReport(ctx, ep, results)
				log.Info("Project scoring completed",
					zap.String("project_id", prj.UUID.String()),
					zap.String("name", prj.Name),
				)
				log.Info("Dependency-Track scoring run completed")
				return nil
			}
		}
	}

	return nil
}

// profileTagPrefix returns the tag prefix for a given profile key.
// By default, interlynk
func profileTagPrefix(profile string) string {
	p := strings.TrimSpace(strings.ToLower(profile))
	if p == "" || p == "interlynk" {
		return "interlynk"
	}
	return p
}

func tagProjectWithScore(ctx context.Context, dTrackClient *dtrack.Client, prj dtrack.Project, finalScore float64) {
	log := logger.FromContext(ctx)

	log.Debug("Tagging projects", zap.Any("tags", prj.Tags))
	// remove old score
	prj.Tags = lo.Filter(prj.Tags, func(t dtrack.Tag, _ int) bool {
		return !strings.HasPrefix(t.Name, "sbomqs=")
	})

	tag := fmt.Sprintf("sbomqs=%0.1f", finalScore)
	prj.Tags = append(prj.Tags, dtrack.Tag{Name: tag})

	log.Debug("Updating project tags", zap.Any("tags", prj.Tags))

	_, err := dTrackClient.Project.Update(ctx, prj)
	if err != nil {
		log.Error("Failed to update project tag", zap.Any("tags", prj.Tags), zap.Error(err))
	}
}
