
# Ignore Semantics in sbomqs Scoring

This document explains the meaning and correct use of `Ignore` in both **profile**
and **comprehensive** scoring. Understanding this distinction is critical: a feature
marked `ignored: true` is excluded from score calculation, while `ignored: false`
with score `0` actively penalises the average.

---

## What Does `Ignore` Mean?

`Ignore` is **not** a softness signal. It answers one narrow question:

> **"Does an evaluation context exist for this field?"**

- `Ignore=false` → context exists: evaluate and score (pass or fail)
- `Ignore=true`  → no context: skip entirely (field is N/A for this SBOM)

### Score 0 vs Ignore: True — Critical Difference

| Scenario | Score | Ignore | Effect on average |
|----------|-------|--------|-------------------|
| Feature present but invalid | `0.0` | `false` | **Drags the average down** — counts as 0 |
| Feature not applicable (e.g. SPDX doesn't support signatures) | `0.0` | `true` | **No impact** — excluded entirely |
| Optional field absent (e.g. no source hash) | `0.0` | `true` | **No impact** — excluded entirely |

> `Ignore=true` should only be set when there is genuinely no basis for evaluation,
> not when the data is simply missing or wrong.

---

## Profile Scoring (`ProfFeatScore`)

Profile scoring evaluates compliance against standards such as NTIA, BSI, and
Interlynk. Every field evaluation returns:

```go
type ProfFeatScore struct {
    Score  float64 // 0–10
    Desc   string
    Ignore bool    // true = skip this field
}
```

### Tier-by-Tier Behaviour

#### Required Fields (§5.2)

"MUST always be provided." `Ignore=true` means the field cannot be evaluated at all
(tool or format limitation).

| Situation | Ignore | Score | Reason |
|-----------|--------|-------|--------|
| Format does not support the field (e.g. signature in SPDX) | `true` | 0 | No field to read |
| Tool cannot yet read the field | `true` | 0 | Interface not extended |
| No components in SBOM | `false` | 0 | Absence = failure |
| Components exist, field absent | `false` | 0 | Compliance violation |
| Components exist, field invalid | `false` | 0 | Wrong data |
| Components exist, field valid | `false` | 10 | Pass |

#### Additional Fields (§5.3)

"MUST be provided if they exist and prerequisites are met." `Ignore` tracks whether
the prerequisite is satisfied.

Example: `comp_concluded_license`

| Situation | Ignore | Score | Reason |
|-----------|--------|-------|--------|
| No components in SBOM | `true` | 0 | No context |
| Components exist, none have concluded licence | `true` | 0 | Prerequisite not met |
| Components exist, concluded licence is `NOASSERTION` | `false` | 0 | Prerequisite met, invalid |
| Components exist, concluded licence is valid | `false` | 10 | Pass |

#### Optional Fields (§5.4)

"MAY be provided if they exist." Optional fields never enter the score formula.
`Ignore` semantics apply for consistency but have no scoring impact.

### Effect on Profile Score

`ComputeInterlynkProfScore` (line ~301):

```go
if res.Required && !res.Ignore {
    total++          // counted only when evaluable
    totalScore += res.Score
} else if res.Additional && !res.Ignore {
    total++          // counted only when prerequisite met
    totalScore += res.Score
}
// Optional: never counted
```

| Tier | Ignore=false | Ignore=true |
|------|-------------|-------------|
| Required | counted (score 0–10) | **excluded** — no penalty |
| Additional | counted (score 0–10) | excluded — no penalty |
| Optional | excluded | excluded |

---

## Comprehensive Scoring (`ComprFeatScore`)

Comprehensive scoring evaluates SBOM quality across categories (Identification,
Provenance, Integrity, etc.). Each feature returns:

```go
type ComprFeatScore struct {
    Score  float64
    Desc   string  // e.g. "235/247 have versions"
    Ignore bool
}
```

### Effect on Comprehensive Score

`ComputeCategoryScore` (line ~212) does a **weighted average over non-ignored features
only**. Ignored features are excluded from **both numerator and denominator** via
weight renormalisation:

```go
for _, feature := range features {
    if feature.Ignored {
        continue        // excluded from weight sum AND score computation
    }
    totalFeatureWeight += feature.Weight
    // ...
}
```

This differs from the **v1 legacy engine** (`AvgScore` in `pkg/scorer/scores.go:43`):
v1 skips ignored features in the numerator but **still counts them in the denominator**
(`len(scs)`), so a ignored feature effectively contributes 0. The v2 engine properly
renormalises weights.

---

## Field Reference: Ignored Features by Format

### SPDX — Fields that return `Ignore: true`

| Feature | Category | Reason |
|---------|----------|--------|
| `sbom_supplier` | Provenance | SPDX has no document-level supplier concept. Creator (`createdBy` / `creators`) already covers this role. |
| `sbom_signature` | Integrity | SPDX specification does not support document-level signatures. |
| `sbom_completeness_declared` | Completeness | SPDX has no native "completeness declared" field. |

### SPDX 2.3 — Fields that were `Ignore: true` but are now evaluated

| Feature | Change | Reason |
|---------|--------|--------|
| `sbom_lifecycle` | `Ignore: true` → `Ignore: false` | SPDX 2.3 extracts lifecycle from `CreationInfo.CreatorComment`. The spec provides a way to capture this via the creator comment, so it is evaluated (not ignored). |

### CycloneDX — Fields that return `Ignore: true`

| Feature | Category | Reason |
|---------|----------|--------|
| `sbom_schema_validation` | Structural | Schema validation skipped for non-JSON formats. |

### Fields that return `Ignore: true` for ALL formats (tool limitation)

| Feature | Category | Reason |
|---------|----------|--------|
| `comp_filename` | Completeness | CDX has no native filename field; interface not yet extended. |
| `comp_executable_property` | Completeness | No native SPDX/CDX field for executable flag. |
| `comp_archive_property` | Completeness | No native SPDX/CDX field for archive flag. |
| `comp_structured_property` | Completeness | No native SPDX/CDX field for structured flag. |

### Fields that return `Ignore: true` when optional and absent

| Feature | Profile | Condition |
|---------|---------|-----------|
| `comp_source_code_hash` | BSI v2.1 | No component declares source code hash |
| `comp_deployable_hash` | BSI v2.1 | No component declares deployable hash |

---

## Quick Decision Guide

```
Is the field a tool/format limitation (no corresponding concept)?
    YES → Ignore=true, Score=0

Is this a Required field?
    Format doesn't support it?         → Ignore=true, Score=0   (tool limitation)
    No components in SBOM?               → Ignore=false, Score=0  (absence = failure)
    Components present, field absent?     → Ignore=false, Score=0  (compliance violation)
    Components present, field invalid?  → Ignore=false, Score=0  (invalid data)
    Components present, field valid?    → Ignore=false, Score=10 (pass)

Is this an Additional field?
    No components in SBOM?              → Ignore=true, Score=0   (no context)
    Components exist, field absent?     → Ignore=true, Score=0   (prerequisite not met)
    Components exist, field invalid?    → Ignore=false, Score=0  (prerequisite met, fail)
    Components exist, field valid?      → Ignore=false, Score=10 (pass)

Is this an Optional field?
    Apply same logic as Additional for consistency (no scoring impact either way).
```
