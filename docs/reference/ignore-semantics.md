
# Ignore Semantics in Profile Scoring

This document explains the meaning and correct use of `Ignore` across all three field tiers
(Required, Additional, Optional) in sbomqs profile evaluation.

## What Does `Ignore` Mean?

Every profile field evaluation returns a `ProfFeatScore`:

```go
type ProfFeatScore struct {
    Score  float64 // 0–10
    Desc   string
    Ignore bool    // true = no basis for evaluation; skip this field
}
```

`Ignore` is **not** a softness signal. It answers one narrow question:

> **"Does an evaluation context exist for this field?"**

- `Ignore=false` context exists: evaluate and score (pass or fail)
- `Ignore=true`  no context: skip entirely (field is N/A)

## The Four Situations

| Situation | Ignore | Score | Meaning |
|-----------|--------|-------|---------|
| Field present and valid | `false` | 10 | Pass |
| Field present but invalid / wrong value | `false` | 0 | Fail |
| Field absent (expected but not provided) | `false` | 0 | Fail compliance violation |
| No context to evaluate | `true` | 0 | N/A skip |

The key distinction is between **"field absent"** and **"no context to evaluate"**. A missing
field is still evaluatable the tool can look for it, find it absent, and score it as a
failure. "No context" means the tool has no way to look for the field in the first place.

> `Ignore=true` should only be set when there is genuinely no basis for evaluation,
> not when the data is simply missing or wrong.

## Tier-by-Tier Behaviour

### Required Fields (§5.2)

The standard says: **"MUST always be provided."** There is no condition. The field is
unconditionally mandatory. So `Ignore` answers only one question:
**"Can the tool even attempt to evaluate this field?"**

| Situation | Ignore | Score | Reason |
|-----------|--------|-------|--------|
| SBOM format does not support the field at all (e.g. signature in SPDX) | `true` | 0 | Tool limitation no field to read |
| Tool interface cannot yet read the field (e.g. `comp_filename`, `comp_executable_property`) | `true` | 0 | Tool limitation interface not extended |
| No components in SBOM | `false` | 0 | SBOM exists, field is required absence is a failure |
| Components exist, field absent | `false` | 0 | Supported field simply not provided compliance violation |
| Components exist, field present but invalid (e.g. `NOASSERTION`, `NONE`) | `false` | 0 | Data present but wrong failure |
| Components exist, field present and valid | `false` | 10 | Pass |

**Key point:** "Field absent" for a Required field is `Ignore=false, Score=0` a clear
failure. The SBOM format supports the field and the tool can evaluate it; the creator
simply did not provide it. That is a compliance violation, not an N/A.

`Ignore=true` for Required fields is exclusively a **tool limitation** either the SBOM
format has no corresponding concept, or the sbomqs interface does not yet expose it.
Current examples:

- `comp_filename` SPDX has `PackageFileName`; CDX has no native field. Interface not
  yet extended → `Ignore=true`
- `comp_executable_property`, `comp_archive_property`, `comp_structured_property` no
  native SPDX/CDX field for any of these → `Ignore=true`
- `sbom_signature` in SPDX the format has no signature concept → `Ignore=true`

These are fundamentally different from `comp_deployable_hash` where SHA-512 is absent:
that is `Ignore=false, Score=0` because the format supports checksums and the tool
can read them the creator just didn't provide SHA-512.

### Additional Fields (§5.3)

The standard says: **"MUST be provided if they exist and their prerequisites are met."**
The field is conditional: if the prerequisite condition is not met, the field does not
apply. So `Ignore` tracks whether the prerequisite is satisfied.

Example: `comp_concluded_license`

| Situation | Ignore | Score | Reason |
|-----------|--------|-------|--------|
| No components in SBOM | `true` | 0 | Component-level field can't be evaluated at all |
| Components exist, none have any concluded licence field | `true` | 0 | Prerequisite not met data doesn't exist, field doesn't apply |
| Components exist, concluded licence present but `NOASSERTION` | `false` | 0 | Prerequisite IS met data exists, just invalid |
| Components exist, concluded licence is a valid SPDX ID | `false` | 10 | Prerequisite met, data valid pass |

The prerequisite here is "does concluded licence data exist at all?" When no component
provides it, the condition is unmet and `Ignore=true`. Once at least one component has
a concluded licence field even if the value is invalid the condition is met and
`Ignore=false` (the evaluator must judge it).

### Optional Fields (§5.4)

The standard says: **"MAY be provided if they exist."** Optional fields never enter the
InterlynkScore formula regardless of `Ignore`. They affect only the `Passed` boolean
in the reporter summary.

The same `Ignore` semantics apply for consistency:

- No context to evaluate → `Ignore=true`
- Context exists (data is present or absent) → `Ignore=false`

But since Optional fields are excluded from scoring in all cases, the distinction has
no effect on the final score.

## Effect on Scoring

The `ComputeInterlynkProfScore` formula handles each tier as follows:

```go
if res.Required {
    // Always counted Ignore=true means score 0 is included in denominator
    total++
    totalScore += res.Score
} else if res.Additional && !res.Ignore {
    // Counted only when prerequisite is met (data exists)
    total++
    totalScore += res.Score
}
// Optional: never counted
```

This means:

| Tier | Ignore=false | Ignore=true |
|------|-------------|-------------|
| Required | counted (score 0–10) | currently also counted (score=0) penalises |
| Additional | counted (score 0–10) | excluded no penalty |
| Optional | excluded | excluded |

> **Design note:** Whether a Required field with `Ignore=true` (tool limitation) should
> penalise the score is an open design question. The current implementation includes it
> at score=0, penalising profiles for fields the tool cannot yet evaluate. An alternative
> (Option B) would exclude such fields from the denominator and surface them separately
> in the reporter as "N/A not evaluated."

## Quick Decision Guide

```
Is the field a tool limitation (format has no concept, or interface not yet built)?
    YES → Ignore=true, Score=0

Is this a Required field?
    No components in SBOM?         → Ignore=false, Score=0   (absence = failure)
    Components present, field absent?  → Ignore=false, Score=0   (absence = failure)
    Components present, field invalid? → Ignore=false, Score=0   (invalid = failure)
    Components present, field valid?   → Ignore=false, Score=10  (pass)

Is this an Additional field?
    No components in SBOM?              → Ignore=true, Score=0   (no context)
    Components exist, field absent?     → Ignore=true, Score=0   (prerequisite not met)
    Components exist, field invalid?    → Ignore=false, Score=0  (prerequisite met, fail)
    Components exist, field valid?      → Ignore=false, Score=10 (pass)

Is this an Optional field?
    Apply same logic as Additional for consistency (no scoring impact either way).
```
