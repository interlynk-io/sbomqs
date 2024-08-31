package sbom

type GetSignature interface {
	CheckSignatureExists() bool
	Key() string
	Value() string
	PublicKey() string
	Algorithm() string
}

type signature struct {
	keyID           string
	algorithm       string
	value           string
	publicKey       string
	certificatePath string
	certificate     string
	timestamp       string
}

func (s signature) CheckSignatureExists() bool {
	return s.keyID != "" && s.algorithm != "" && s.value != "" && (s.publicKey != "" || s.certificate != "")
}

func (s signature) Key() string {
	return s.keyID
}

func (s signature) Value() string {
	return s.value
}

func (s signature) PublicKey() string {
	return s.publicKey
}

func (s signature) Algorithm() string {
	return s.algorithm
}
