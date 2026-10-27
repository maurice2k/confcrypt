package processor

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/format"
)

// Document is a parsed structured file (YAML, JSON or env). Its roots can be
// inspected and mutated through doc.Node and written back with Marshal:
// losslessly for JSON, with comments and blank lines preserved for YAML.
type Document struct {
	format   FileFormat
	yamlDocs []*yaml.Node
	jsonDoc  *doc.JSONDocument
	envFile  *EnvFile
	roots    []doc.Node
}

// ParseDocument parses content in the given format.
func ParseDocument(content []byte, fileFormat FileFormat) (*Document, error) {
	d := &Document{format: fileFormat}
	switch fileFormat {
	case FormatYAML:
		docs, err := decodeYAMLDocs(content)
		if err != nil {
			return nil, err
		}
		for _, n := range docs {
			preserveBlankLines(n, content)
			if root := doc.FromYAML(n); root != nil {
				d.roots = append(d.roots, root)
			}
		}
		d.yamlDocs = docs
	case FormatJSON:
		jd, err := doc.ParseJSON(content)
		if err != nil {
			return nil, err
		}
		d.jsonDoc = jd
		d.roots = []doc.Node{jd.Root()}
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .env file: %w", err)
		}
		d.envFile = envFile
		d.roots = []doc.Node{envDoc(envFile)}
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
	return d, nil
}

// Roots returns the document roots: one per YAML document, exactly one for
// JSON and env files.
func (d *Document) Roots() []doc.Node {
	return d.roots
}

// Marshal renders the document back to bytes.
func (d *Document) Marshal() ([]byte, error) {
	switch d.format {
	case FormatYAML:
		return marshalYAMLDocs(d.yamlDocs)
	case FormatJSON:
		return d.jsonDoc.Marshal()
	case FormatEnv:
		return d.envFile.Marshal(), nil
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}

// NewScalar creates a detached scalar node suitable for this document.
func (d *Document) NewScalar(value string, typ format.ValueType) doc.Node {
	if d.format == FormatJSON {
		return d.jsonDoc.NewScalar(value, typ)
	}
	if typ == format.TypeNull && value == "" {
		value = "null"
	}
	return doc.NewYAMLScalar(value, typ, "")
}

// NewMapping creates a detached empty mapping for this document.
func (d *Document) NewMapping() (doc.Node, error) {
	switch d.format {
	case FormatJSON:
		return d.jsonDoc.NewMapping(), nil
	case FormatYAML:
		return doc.NewYAMLMapping(), nil
	default:
		return nil, fmt.Errorf("env files are flat; nested keys are not possible")
	}
}

// NewSequence creates a detached empty sequence for this document.
func (d *Document) NewSequence() (doc.Node, error) {
	switch d.format {
	case FormatJSON:
		return d.jsonDoc.NewSequence(), nil
	case FormatYAML:
		return doc.NewYAMLSequence(), nil
	default:
		return nil, fmt.Errorf("env files are flat; lists are not possible")
	}
}
