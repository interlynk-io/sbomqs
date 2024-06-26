package sbom

type GetExternalReference interface {
	GetRefType() string
}

type ExternalReference struct {
	RefType string
}

func (e ExternalReference) GetRefType() string {
	return e.RefType
}
