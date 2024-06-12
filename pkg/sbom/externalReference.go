package sbom

type ExternalReference interface {
	RefType() string
}

type externalReference struct {
	refType string
}

func (e externalReference) RefType() string {
	return e.refType
}
