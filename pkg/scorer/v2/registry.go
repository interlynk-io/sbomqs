package v2

var Identification = CategorySpec{
	Name:   "Identification",
	Weight: 10,
	Features: []FeatureSpec{
		{Key: "comp_with_name", Weight: 0.40, Eval: CompWithName},
		{Key: "comp_with_version", Weight: 0.35, Eval: CompWithVersion},
		{Key: "comp_with_ids", Weight: 0.25, Eval: CompWithUniqIDs},
	},
}

var Provenance = CategorySpec{
	Name:   "Provenance",
	Weight: 12,
	Features: []FeatureSpec{
		{Key: "sbom_creation_timestamp", Weight: 0.20, Eval: SBOMCreationTime},
		{Key: "sbom_authors", Weight: 0.20, Eval: SBOMAuthors},
		{Key: "sbom_tool_version", Weight: 0.20, Eval: SBOMToolVersion},
		{Key: "sbom_supplier", Weight: 0.15, Eval: SBOMSupplier},
		{Key: "sbom_namespace", Weight: 0.15, Eval: SBOMNamespace},
		{Key: "sbom_lifecycle", Weight: 0.10, Eval: SBOMLifecycle},
	},
}

var Integrity = CategorySpec{
	Name:   "Integrity",
	Weight: 15,
	Features: []FeatureSpec{
		{Key: "sbom_signature", Weight: 0.10, Eval: SBOMDDocSignature},
		{Key: "comp_with_hash", Weight: 0.10, Eval: CompWithChecksum},
	},
}

var Completeness = CategorySpec{
	Name:   "Completeness",
	Weight: 12,
	Features: []FeatureSpec{
		{Key: "sbom_signature", Weight: 0.10, Eval: SBOMDDocSignature},
		{Key: "comp_with_dependencies", Weight: 0.25, Eval: CompWithDependencies},
		{Key: "comp_with_declared_completeness", Weight: 0.15, Eval: CompWithDeclaredCompleteness},
		{Key: "primary_component", Weight: 0.15, Eval: PrimaryComponent},
		{Key: "comp_with_declared_completeness", Weight: 0.15, Eval: CompWithDeclaredCompleteness},
	},
}
