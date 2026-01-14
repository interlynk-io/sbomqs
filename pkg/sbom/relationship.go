package sbom

type GetRelationships interface {
	GetFrom() string
	GetTo() string
	GetType() string
}

type Relationship struct {
	From string // component ID
	To   string // component ID
	Type string // relationship type
}

func (r Relationship) GetFrom() string {
	return r.From
}

func (r Relationship) GetTo() string {
	return r.To
}

func (r Relationship) GetType() string {
	return r.Type
}
