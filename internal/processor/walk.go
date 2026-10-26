package processor

import (
	"fmt"
	"strings"

	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/format"
)

// This file holds the format-independent walks over doc.Node trees:
// encrypting/decrypting values in place, collecting unencrypted matches
// for check, and collecting encrypted values for the MAC and detection.
// YAML, JSON and env files all go through these.

// transformNode encrypts or decrypts matching values in place and reports
// whether anything changed. Aliases (YAML) are only followed on encrypt
// when their key matched, so a secret referenced through an alias is
// encrypted at its anchor instead of silently staying in plaintext; anchors
// themselves are visited where they are defined.
func (p *Processor) transformNode(node doc.Node, path []string, encrypt bool) (bool, error) {
	if node == nil {
		return false, nil
	}
	modified := false

	switch node.Kind() {
	case doc.Mapping:
		for i := 0; i < node.Len(); i++ {
			key := node.Key(i)
			value := node.Item(i)
			currentPath := clonePath(path, key)
			matched := encrypt && p.matcher.ShouldEncrypt(key, currentPath)

			if value.IsAlias() {
				if !matched {
					continue
				}
				value = value.Target()
			}

			switch {
			case value.Kind() == doc.Scalar:
				if encrypt {
					if matched && !format.IsEncrypted(value.Value()) {
						if err := p.encryptNode(value, currentPath); err != nil {
							return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(currentPath, "."), err)
						}
						modified = true
					}
				} else if format.IsEncrypted(value.Value()) {
					if err := p.decryptNode(value, currentPath); err != nil {
						return false, fmt.Errorf("failed to decrypt %s: %w", strings.Join(currentPath, "."), err)
					}
					modified = true
				}

			case matched && value.Kind() == doc.Sequence:
				// A matched key whose value is a list: encrypt the scalar items
				m, err := p.encryptMatchedSequence(value, currentPath)
				if err != nil {
					return false, err
				}
				modified = modified || m

			default:
				m, err := p.transformNode(value, currentPath, encrypt)
				if err != nil {
					return false, err
				}
				modified = modified || m
			}
		}

	case doc.Sequence:
		for i := 0; i < node.Len(); i++ {
			item := node.Item(i)
			if item.IsAlias() {
				continue
			}
			if item.Kind() == doc.Scalar {
				// Scalar list items are encrypted only under a matched key
				// (handled above), but any encrypted item must decrypt here
				if !encrypt && format.IsEncrypted(item.Value()) {
					if err := p.decryptNode(item, path); err != nil {
						return false, fmt.Errorf("failed to decrypt %s: %w", strings.Join(path, "."), err)
					}
					modified = true
				}
				continue
			}
			m, err := p.transformNode(item, path, encrypt)
			if err != nil {
				return false, err
			}
			modified = modified || m
		}
	}

	return modified, nil
}

// encryptMatchedSequence encrypts the scalar items of a sequence whose key
// matched the encryption rules. Nested sequences inherit the match;
// mappings inside the list are traversed with normal key matching.
func (p *Processor) encryptMatchedSequence(node doc.Node, path []string) (bool, error) {
	modified := false
	for i := 0; i < node.Len(); i++ {
		item := node.Item(i)
		if item.IsAlias() {
			continue
		}
		switch item.Kind() {
		case doc.Scalar:
			if format.IsEncrypted(item.Value()) {
				continue
			}
			if err := p.encryptNode(item, path); err != nil {
				return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(path, "."), err)
			}
			modified = true
		case doc.Sequence:
			m, err := p.encryptMatchedSequence(item, path)
			if err != nil {
				return false, err
			}
			modified = modified || m
		default:
			m, err := p.transformNode(item, path, true)
			if err != nil {
				return false, err
			}
			modified = modified || m
		}
	}
	return modified, nil
}

// encryptNode replaces a scalar's value with its ENC[...] form, keeping the
// portable type and any format-specific tag inside the ciphertext.
func (p *Processor) encryptNode(n doc.Node, path []string) error {
	ev, err := p.encryptPlaintextTagged(path, []byte(n.Value()), n.Type(), n.Tag())
	if err != nil {
		return err
	}
	n.SetScalar(format.FormatEncryptedValue(ev), format.TypeString, "")
	return nil
}

// decryptNode replaces an ENC[...] scalar with its plaintext, restoring the
// original type and tag.
func (p *Processor) decryptNode(n doc.Node, path []string) error {
	ev, err := format.ParseEncryptedValue(n.Value())
	if err != nil {
		return err
	}
	plaintext, err := p.decryptAESGCM(ev.Data, ev.IV, ev.Tag)
	if err != nil {
		return err
	}
	p.recordCiphertext(path, plaintext, ev)
	n.SetScalar(string(plaintext), ev.Type, ev.YAMLTag)
	return nil
}

// collectUnencrypted reports every matching value that is still in
// plaintext, mirroring exactly what transformNode would encrypt.
func (p *Processor) collectUnencrypted(node doc.Node, path []string, results *[]MatchResult) {
	if node == nil {
		return
	}
	switch node.Kind() {
	case doc.Mapping:
		for i := 0; i < node.Len(); i++ {
			key := node.Key(i)
			value := node.Item(i)
			currentPath := clonePath(path, key)
			matched := p.matcher.ShouldEncrypt(key, currentPath)

			if value.IsAlias() {
				if !matched {
					continue
				}
				value = value.Target()
			}

			switch {
			case value.Kind() == doc.Scalar:
				if matched && !format.IsEncrypted(value.Value()) {
					*results = append(*results, MatchResult{
						Path:      currentPath,
						KeyName:   key,
						Value:     value.Value(),
						Encrypted: false,
					})
				}
			case matched && value.Kind() == doc.Sequence:
				p.collectUnencryptedMatchedSequence(value, path, key, results)
			default:
				p.collectUnencrypted(value, currentPath, results)
			}
		}

	case doc.Sequence:
		for i := 0; i < node.Len(); i++ {
			item := node.Item(i)
			if item.IsAlias() {
				continue
			}
			p.collectUnencrypted(item, path, results)
		}
	}
}

// collectUnencryptedMatchedSequence reports unencrypted scalar items of a
// sequence whose key matched the encryption rules.
func (p *Processor) collectUnencryptedMatchedSequence(node doc.Node, parentPath []string, key string, results *[]MatchResult) {
	for i := 0; i < node.Len(); i++ {
		item := node.Item(i)
		if item.IsAlias() {
			continue
		}
		switch item.Kind() {
		case doc.Scalar:
			if !format.IsEncrypted(item.Value()) {
				*results = append(*results, MatchResult{
					Path:      clonePath(parentPath, fmt.Sprintf("%s[%d]", key, i)),
					KeyName:   key,
					Value:     item.Value(),
					Encrypted: false,
				})
			}
		case doc.Sequence:
			p.collectUnencryptedMatchedSequence(item, parentPath, fmt.Sprintf("%s[%d]", key, i), results)
		default:
			p.collectUnencrypted(item, clonePath(parentPath, key), results)
		}
	}
}

// collectEncryptedNodeValues appends every ENC[...] scalar found in the
// tree. Aliases are skipped since their anchors are visited directly.
func collectEncryptedNodeValues(node doc.Node, values []string) []string {
	if node == nil {
		return values
	}
	switch node.Kind() {
	case doc.Scalar:
		if format.IsEncrypted(node.Value()) {
			values = append(values, node.Value())
		}
	default:
		for i := 0; i < node.Len(); i++ {
			item := node.Item(i)
			if item.IsAlias() {
				continue
			}
			values = collectEncryptedNodeValues(item, values)
		}
	}
	return values
}
