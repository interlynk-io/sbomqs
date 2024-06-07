package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRetrieveFiles(t *testing.T) {
	// Create test directories
	err := os.MkdirAll("testDir", os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	defer os.RemoveAll("testDir")

	err = os.WriteFile("testDir/testFile.txt", []byte("test content file1"), os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	err = os.MkdirAll("testDir1", os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	defer os.RemoveAll("testDir1")

	err = os.WriteFile("testDir1/testFile1.txt", []byte("test content in testDir1/testFile1.txt"), os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	err = os.MkdirAll("testDir2", os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	defer os.RemoveAll("testDir2")

	err = os.WriteFile("testDir2/testFile2.txt", []byte("test content"), os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	// Test with a single file
	ctx := context.Background()
	files, paths, err := retrieveFiles(ctx, []string{"testDir/testFile.txt"})
	if err != nil {
		t.Errorf("Error retrieving files: %s", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}
	if len(paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(paths))
	}
	if files[0] != "testDir/testFile.txt" {
		t.Errorf("Expected file path to be 'testDir/testFile.txt', got '%s'", files[0])
	}

	// Test with multiple files
	files, paths, err = retrieveFiles(ctx, []string{"testDir1/testFile1.txt", "testDir2/testFile2.txt"})
	if err != nil {
		t.Errorf("Error retrieving files: %s", err)
	}
	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(paths))
	}
	if files[0] != "testDir1/testFile1.txt" {
		t.Errorf("Expected file path to be 'testDir1/testFile1.txt', got '%s'", files[0])
	}
	if files[1] != "testDir2/testFile2.txt" {
		t.Errorf("Expected file path to be 'testDir2/testFile2.txt', got '%s'", files[1])
	}

	// Test with an error
	files, paths, err = retrieveFiles(ctx, []string{"nonExistentDir"})
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if len(files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(files))
	}
	if len(paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(paths))
	}
	if paths[0] != "nonExistentDir" {
		t.Errorf("Expected path to be 'nonExistentDir', got '%s'", paths[0])
	}
}

func TestGetSbom(t *testing.T) {
	ctx := context.Background()
	logger.FromContext(ctx)

	t.Run("file open error", func(t *testing.T) {
		nonexistentFile := "nonexistentfile.txt"

		doc, err := getSbom(ctx, nonexistentFile, nil)
		assert.Nil(t, doc)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("sbom document creation error", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "testfile*.txt")
		assert.NoError(t, err)
		defer os.Remove(tempFile.Name())

		mockSBOM := new(MockSBOMDocument)
		mockSBOM.On("NewSBOMDocument", ctx, mock.Anything).Return(nil, errors.New("failed to create sbom document"))

		doc, err := getSbom(ctx, tempFile.Name(), mockSBOM.NewSBOMDocument)
		assert.Nil(t, doc)
		assert.Error(t, err)
		assert.Equal(t, "failed to create sbom document", err.Error())
		mockSBOM.AssertExpectations(t)
	})

	t.Run("successful sbom document creation", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "testfile*.txt")
		assert.NoError(t, err)
		defer os.Remove(tempFile.Name())

		dummyDoc := createDummyDocument()
		mockSBOM := new(MockSBOMDocument)
		mockSBOM.On("NewSBOMDocument", ctx, mock.Anything).Return(dummyDoc, nil)

		doc, err := getSbom(ctx, tempFile.Name(), mockSBOM.NewSBOMDocument)
		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.Equal(t, dummyDoc, doc)

		mockSBOM.AssertExpectations(t)
	})
}

type MockSBOMDocument struct {
	mock.Mock
}

func (m *MockSBOMDocument) NewSBOMDocument(ctx context.Context, f io.ReadSeeker) (sbom.Document, error) {
	args := m.Called(ctx, f)
	// Use args.Get to handle nil return values correctly
	if args.Get(0) != nil {
		return args.Get(0).(sbom.Document), args.Error(1)
	}
	return nil, args.Error(1)
}

type MockScorer struct {
	mock.Mock
}

func (m *MockScorer) AddFilter(name string, ftype scorer.FilterType) {
	m.Called(name, ftype)
}

func (m *MockScorer) Score() scorer.Scores {
	args := m.Called()
	return args.Get(0).(scorer.Scores)
}

func TestScore(t *testing.T) {
	ctx := context.Background()
	doc := createDummyDocument()
	sr := scorer.NewScorer(ctx, doc)
	score := sr.Score()
	fmt.Println("Score: ", score.AvgScore())
}

// Mock implementations of the interfaces
type MockDocument struct {
	spec         sbom.Spec
	components   []sbom.Component
	relations    []sbom.Relation
	authors      []sbom.Author
	tools        []sbom.Tool
	logs         []string
	primary      bool
	lifecycles   []string
	manufacturer sbom.Manufacturer
	supplier     sbom.Supplier
}

func (m MockDocument) Spec() sbom.Spec                 { return m.spec }
func (m MockDocument) Components() []sbom.Component    { return m.components }
func (m MockDocument) Relations() []sbom.Relation      { return m.relations }
func (m MockDocument) Authors() []sbom.Author          { return m.authors }
func (m MockDocument) Tools() []sbom.Tool              { return m.tools }
func (m MockDocument) Logs() []string                  { return m.logs }
func (m MockDocument) PrimaryComponent() bool          { return m.primary }
func (m MockDocument) Lifecycles() []string            { return m.lifecycles }
func (m MockDocument) Manufacturer() sbom.Manufacturer { return m.manufacturer }
func (m MockDocument) Supplier() sbom.Supplier         { return m.supplier }

type MockSpec struct {
	version            string
	format             string
	name               string
	isReqFieldsPresent bool
	licenses           []licenses.License
	creationTimestamp  string
	namespace          string
	uri                string
}

func (s MockSpec) Version() string              { return s.version }
func (s MockSpec) FileFormat() string           { return s.format }
func (s MockSpec) Parsable() bool               { return true }
func (s MockSpec) Name() string                 { return s.name }
func (s MockSpec) RequiredFields() bool         { return s.isReqFieldsPresent }
func (s MockSpec) CreationTimestamp() string    { return s.creationTimestamp }
func (s MockSpec) Licenses() []licenses.License { return s.licenses }
func (s MockSpec) Namespace() string            { return s.namespace }
func (s MockSpec) URI() string                  { return s.uri }

type MockComponent struct {
	id                 string
	supplierName       string
	name               string
	version            string
	cpes               []cpe.CPE
	purls              []purl.PURL
	licenses           []licenses.License
	checksums          []sbom.Checksum
	purpose            string
	isReqFieldsPresent bool
	supplier           sbom.Supplier
	manufacturer       sbom.Manufacturer
	dependenciesCount  int
	sourceCodeUrl      string
	downloadLocation   string
	sourceCodeHash     string
	isPrimary          bool
	hasRelationships   bool
	relationshipState  string
}

func (c MockComponent) ID() string                      { return c.id }
func (c MockComponent) SupplierName() string            { return c.supplierName }
func (c MockComponent) Name() string                    { return c.name }
func (c MockComponent) Version() string                 { return c.version }
func (c MockComponent) Cpes() []cpe.CPE                 { return c.cpes }
func (c MockComponent) Purls() []purl.PURL              { return c.purls }
func (c MockComponent) Licenses() []licenses.License    { return c.licenses }
func (c MockComponent) Checksums() []sbom.Checksum      { return c.checksums }
func (c MockComponent) PrimaryPurpose() string          { return c.purpose }
func (c MockComponent) RequiredFields() bool            { return c.isReqFieldsPresent }
func (c MockComponent) Supplier() sbom.Supplier         { return c.supplier }
func (c MockComponent) Manufacturer() sbom.Manufacturer { return c.manufacturer }
func (c MockComponent) CountOfDependencies() int        { return c.dependenciesCount }
func (c MockComponent) SourceCodeUrl() string           { return c.sourceCodeUrl }
func (c MockComponent) DownloadLocationUrl() string     { return c.downloadLocation }
func (c MockComponent) SourceCodeHash() string          { return c.sourceCodeHash }
func (c MockComponent) IsPrimaryComponent() bool        { return c.isPrimary }
func (c MockComponent) HasRelationShips() bool          { return c.hasRelationships }
func (c MockComponent) RelationShipState() string       { return c.relationshipState }

type MockRelation struct {
	from string
	to   string
}

func (r MockRelation) From() string { return r.from }
func (r MockRelation) To() string   { return r.to }

type MockAuthor struct {
	name       string
	email      string
	authorType string
}

func (a MockAuthor) Name() string  { return a.name }
func (a MockAuthor) Type() string  { return a.authorType }
func (a MockAuthor) Email() string { return a.email }

type MockTool struct {
	name    string
	version string
}

func (t MockTool) Name() string    { return t.name }
func (t MockTool) Version() string { return t.version }

type MockManufacturer struct {
	name     string
	url      string
	email    string
	contacts []sbom.Contact
}

func (m MockManufacturer) Name() string             { return m.name }
func (m MockManufacturer) Url() string              { return m.url }
func (m MockManufacturer) Email() string            { return m.email }
func (m MockManufacturer) Contacts() []sbom.Contact { return m.contacts }

type MockSupplier struct {
	name     string
	email    string
	url      string
	contacts []sbom.Contact
}

func (s MockSupplier) Name() string             { return s.name }
func (s MockSupplier) Email() string            { return s.email }
func (s MockSupplier) Url() string              { return s.url }
func (s MockSupplier) Contacts() []sbom.Contact { return s.contacts }

func createDummyDocument() sbom.Document {
	spec := MockSpec{
		version:            "SPDX-2.2",
		format:             "spdx",
		name:               "xyz-0.1.0",
		isReqFieldsPresent: true,
		licenses:           []licenses.License{}, // Populate as needed
		creationTimestamp:  "2020-07-23T18:30:22Z",
		namespace:          "http://spdx.org/spdxdocs/spdx-document-xyz",
		uri:                "",
	}

	component := MockComponent{
		id:                "SPDXRef-Package-xyz",
		supplierName:      "Example Inc.",
		name:              "xyz",
		version:           "0.1.0",
		downloadLocation:  "git+ssh://gitlab.example.com:3389/products/xyz.git@b2c358080011af6a366d2512a25a379fbe7b1f78",
		sourceCodeUrl:     "https://example.com/source-code-url",
		sourceCodeHash:    "examplehash",
		isPrimary:         true,
		hasRelationships:  false,
		relationshipState: "example-state",
	}

	author := MockAuthor{
		name:       "John Doe",
		email:      "john.doe@example.com",
		authorType: "person",
	}

	tool := MockTool{
		name:    "Example Tool",
		version: "1.0.0",
	}

	manufacturer := MockManufacturer{
		name:  "Example Manufacturer",
		url:   "https://example.com",
		email: "manufacturer@example.com",
	}

	supplier := MockSupplier{
		name:  "Example Supplier",
		email: "supplier@example.com",
		url:   "https://supplier.com",
	}

	return MockDocument{
		spec:         spec,
		components:   []sbom.Component{component},
		relations:    []sbom.Relation{},
		authors:      []sbom.Author{author},
		tools:        []sbom.Tool{tool},
		logs:         []string{"Log entry 1", "Log entry 2"},
		primary:      true,
		lifecycles:   []string{"development", "production"},
		manufacturer: manufacturer,
		supplier:     supplier,
	}
}
