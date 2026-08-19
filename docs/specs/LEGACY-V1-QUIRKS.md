# Legacy v1 scoring engine: known quirks

Reference for anyone consuming `sbomqs score --legacy` output programmatically,
or re-implementing the v1 feature set to compare scores across tools.

The v1 engine predates sbomqs 2.0 and is kept for backward compatibility. Its
scoring has behaviours that are surprising, undocumented elsewhere, and
discoverable only by reading the Go source. They are recorded here so
integrators know what they are pinning against.

Verified against **v2.0.12**. Each entry cites the code that produces it.

Scope is the v1 engine only. The v2 engine (the default since sbomqs 2.0) is a
separate implementation and does not share these behaviours unless stated.

## Status legend

- **Intended** — deliberate, will not change without a major version bump.
- **Quirk** — surprising but load-bearing; changing it would move every score.

Behaviours that are outright wrong are listed separately under
[Under repair](#under-repair).

---

## 1. Ignored features are not free

**Status: Quirk.** `pkg/scorer/scores.go:47`

```go
func (s scores) AvgScore() float64 {
	score := 0.0
	for _, s := range s.scs {
		if !s.Ignore() {
			score += s.Score()
		}
	}
	return score / float64(s.Count())   // Count() is ALL entries
}
```

A feature marked `ignored` contributes nothing to the numerator but stays in the
denominator. **Marking a feature N/A is numerically identical to scoring it
0.0.** The report prints "N/A (no components)" while applying the maximum
penalty.

This matters most for sparse documents. A CycloneDX file with no components has
35 of its 59 entries ignored, and every one is scored as a failure.

The v2 engine does not do this. `ComputeCategoryScore` drops ignored features
from `totalFeatureWeight`, so N/A genuinely renormalises there. v1 never got
that treatment.

## 2. The headline legacy score includes categories you did not ask for

**Status: Quirk.**

`--legacy` documents five categories: NTIA-minimum-elements, Structural,
Semantic, Quality and Sharing. Those are 23 features. But the report also
carries the `bsi-v1.1` and `bsi-v2.0` category sets, and `avg_score` divides by
**all** of them.

For `samples/photon.spdx.json`:

| | entries | score |
|---|---|---|
| all categories (what `avg_score` uses) | 59 | **5.9545** |
| the five documented legacy categories | 23 | 7.0595 |

Category breakdown for that file: bsi-v2.0 21, bsi-v1.1 15, Quality 8,
NTIA-minimum-elements 7, Structural 4, Semantic 3, Sharing 1.

If you are reproducing the legacy score, you must include the BSI entries.
Averaging only the documented five gives a different, higher number.

## 3. The same feature key appears more than once per report

**Status: Intended**, and a direct consequence of #2.

14 feature keys appear in more than one category. Consumers keying a map on
`feature` alone will silently drop entries. Key on `(category, feature)`.

One of those repeats also had *different implementations* behind the same key.
See "`comp_with_uniq_ids` measured the wrong identifier" below.

## 4. `sbom_dependencies` only counts edges from the primary component

**Status: Intended.** `pkg/scorer/ntia.go`

```go
totalDependencies = len(d.GetDirectDependencies(primary.GetID()))
```

Binary: 10.0 if the primary component has at least one direct dependency, 0.0
otherwise. A document with a rich dependency graph that does not root it at the
primary component scores 0. Arbitrary edges elsewhere in the graph are not
counted.

## 5. `sbom_required_fields` blends document and package halves asymmetrically

**Status: Intended.** `pkg/scorer/semantic.go`

- Document header fails its required fields → **0.0**, regardless of packages.
- Header and all packages pass → **10.0**.
- Header passes, packages partially → **(10 + 10 × have/total) / 2**.

The document header is a gate: a document missing its own required fields is not
spec-valid however complete its packages are. Packages earn partial credit; the
header does not.

## 6. Zero tools scores 0.0 via NaN

**Status: Intended.** `pkg/scorer/quality.go`, `pkg/scorer/score.go:49`

`sbom_with_creator_and_version` computes `withCreatorAndVersion / totalTools`.
With no tools that is `0.0 / 0.0`, which is NaN in Go. `setScore` coerces it:

```go
func (s *score) setScore(f float64) {
	if math.IsNaN(f) { s.score = 0.0 } else { s.score = f }
}
```

The description reads `0/0 tools have creator and version`.

## 7. A missing timestamp produces an empty description

**Status: Quirk.** `pkg/scorer/ntia.go`

`sbomWithTimeStampCheck` only sets a score and description when the timestamp is
non-empty. When it is absent, the function returns having set neither, so the
entry carries the zero value and an **empty** description string:

```
sbom_creation_timestamp   score=0.0   desc=""
```

Every other check emits a description. Consumers rendering `description` should
tolerate the empty string here.

Note the epoch is *not* treated as missing. A document declaring
`1970-01-01T00:00:00Z` scores 10.0, because the check tests format validity, not
plausibility.

## 8. `comp_valid_licenses` counts only SPDX list membership

**Status: Intended.** `pkg/scorer/quality.go`

```go
validLic := lo.CountBy(c.GetLicenses(), func(l licenses.License) bool {
	return l.Spdx()
})
```

Only licences resolved from the embedded SPDX list count. `LicenseRef-*` and
custom identifiers resolve with source `custom` and score **0**, even though
they are valid SPDX expression syntax. A component licensed entirely under
`LicenseRef-Proprietary` scores 0 on this feature.

Per-component ratios are averaged across all components, and components with no
licences at all contribute 0.

## 9. Component enumeration excludes files, snippets and services

**Status: Intended.** `pkg/sbom/spdx.go`, `pkg/sbom/cdx.go`

`Components()` returns SPDX **packages** and CycloneDX **components** only.

- SPDX files and snippets are parsed separately and reached via `Files()`. They
  never appear in a per-component denominator.
- CycloneDX services are read only under `metadata.tools`, never as components.

The CycloneDX **primary component** (`metadata.component`) *is* enumerated. A
document with `"components": []` still reports one component. Reaching a true
zero requires no `metadata.component` either, which is why zero-component edge
cases rarely surface in practice.

---

## Under repair

Behaviours that are wrong rather than merely surprising.

**Each is proposed in an open pull request and none has landed yet.** Everything
above describes v2.0.12 as shipped; this section is what changes if these are
accepted. Update the status here when they merge.

### `sbom_sharable` was unreachable  (PR #732)

Scored **0.0 for essentially every SBOM**, and `list --feature sbom_sharable`
never matched a document.

`meta.freeAnyUse` was populated only from `isFreeAnyUse` in the embedded SPDX
licence list, but the SPDX licence list has never published that field. It
unmarshalled to `false` for all 716 licences, so every document licence
resolving through the SPDX list counted as non-free, `CC0-1.0` included. Since
CC0-1.0 is the `dataLicense` SPDX mandates, every SPDX SBOM scored 0 on the
entire Sharing category.

Now derived from the AboutCode `Public Domain` category. 22 SPDX-listed
identifiers gain the flag.

### `comp_with_uniq_ids` measured the wrong identifier  (PR #734)

Counted components with a non-empty `bom-ref`/`SPDXID`. That is a
document-local handle, present on essentially every component of every real
SBOM, so the check scored ~10.0 unconditionally.

It implements the NTIA element **"Other Unique Identifiers"**: at least one
lookup identifier such as PURL or CPE. Now counts PURL/CPE.

**This lowers scores.** Any SBOM with bom-refs and no purl or cpe drops from
10.0 to 0.0 on this feature. `samples/photon.spdx.json` went 10.0 → 0.0.

The same key under `bsi-v1.1` and `bsi-v2.0` was already correct, so a single
report previously answered the same question two different ways.

### Zero-component documents scored 5.0 on `sbom_required_fields`  (PR #740)

A document with no components took the partial-credit path with an empty package
half and landed on 5.0, describing itself as `Pkg Fields:false` when there were
no packages to have fields. Now scored on the header alone.

N/A was not used here, for the reason in #1: it would have printed "not
applicable" while applying the full penalty.

### Documented grade bands were wrong  (PR #735)

`docs/commands/score.md` listed A as 8.0-10.0. The actual cut lines, from
`ToGrade` in `pkg/scorer/v2/formulae/farmulas.go`, are:

| grade | range |
|---|---|
| A | ≥ 9.0 |
| B | ≥ 8.0 |
| C | ≥ 7.0 |
| D | ≥ 5.0 |
| F | below 5.0 |

---

## Reproducing v1 scores in another tool

If you are implementing a compatibility layer:

1. Use `avg_score = Σ(score of non-ignored entries) / count(ALL entries)`,
   ignored included. Do not renormalise.
2. Include every category present in the report, not just the documented five.
3. Emit features you cannot evaluate as `ignored: true` with a reason rather
   than dropping them. Dropping them shrinks the denominator and inflates the
   average.
4. Key on `(category, feature)`, never `feature` alone.
5. Do not derive the v1 score from the v2 score. The two engines use different
   category taxonomies, weights and missing-data semantics. Dividing a 0-100
   score by 10 does not produce a v1-comparable number.
