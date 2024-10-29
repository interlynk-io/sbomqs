package sbom

type GetExternalReference interface {
	GetRefType() string
	GetRefLocator() string
}

type ExternalReference struct {
	RefType    string
	RefLocator string
}

func (e ExternalReference) GetRefType() string {
	return e.RefType
}

func (e ExternalReference) GetRefLocator() string {
	return e.RefLocator
}
