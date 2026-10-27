package doc

import (
	"fmt"
	"strconv"
	"strings"
)

// Segment is one step of a Path: a mapping key, a sequence index, or the
// append marker "[+]" (meaningful only when setting values).
type Segment struct {
	Key     string
	Index   int
	IsIndex bool
	Append  bool
}

// Path addresses a node inside a document: dotted mapping keys with
// bracketed sequence indices, e.g. db.hosts[0].password. A key containing
// '.', '[', ']' or '"' is written in double quotes with \" and \\ escapes.
type Path []Segment

// ParsePath parses the textual form of a Path.
func ParsePath(s string) (Path, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("empty path")
	}
	var path Path
	i := 0
	expectKey := true // at the start or right after '.'
	for i < len(s) {
		c := s[i]
		switch {
		case expectKey && c == '"':
			key, next, err := parseQuotedSegment(s, i)
			if err != nil {
				return nil, err
			}
			path = append(path, Segment{Key: key})
			i = next
			expectKey = false

		case expectKey && c != '[':
			start := i
			for i < len(s) && s[i] != '.' && s[i] != '[' {
				if s[i] == ']' || s[i] == '"' {
					return nil, fmt.Errorf("invalid path %q: unexpected %q at position %d (quote keys containing special characters)", s, s[i], i+1)
				}
				i++
			}
			if i == start {
				return nil, fmt.Errorf("invalid path %q: empty key at position %d", s, i+1)
			}
			path = append(path, Segment{Key: s[start:i]})
			expectKey = false

		case c == '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("invalid path %q: missing ']'", s)
			}
			inner := s[i+1 : i+end]
			if inner == "+" {
				path = append(path, Segment{Append: true, IsIndex: true})
			} else {
				idx, err := strconv.Atoi(inner)
				if err != nil || idx < 0 || strings.HasPrefix(inner, "+") {
					return nil, fmt.Errorf("invalid path %q: index %q must be a non-negative integer or +", s, inner)
				}
				path = append(path, Segment{Index: idx, IsIndex: true})
			}
			i += end + 1
			expectKey = false

		case c == '.':
			if expectKey {
				return nil, fmt.Errorf("invalid path %q: empty key at position %d", s, i+1)
			}
			i++
			expectKey = true

		default:
			return nil, fmt.Errorf("invalid path %q: unexpected %q at position %d", s, c, i+1)
		}
	}
	if expectKey {
		return nil, fmt.Errorf("invalid path %q: trailing '.'", s)
	}
	return path, nil
}

func parseQuotedSegment(s string, start int) (string, int, error) {
	var sb strings.Builder
	i := start + 1
	for i < len(s) {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", 0, fmt.Errorf("invalid path %q: dangling escape", s)
			}
			sb.WriteByte(s[i+1])
			i += 2
		case '"':
			return sb.String(), i + 1, nil
		default:
			sb.WriteByte(s[i])
			i++
		}
	}
	return "", 0, fmt.Errorf("invalid path %q: unterminated quote", s)
}

// String renders the path in the form ParsePath accepts.
func (p Path) String() string {
	var sb strings.Builder
	for i, seg := range p {
		switch {
		case seg.Append:
			sb.WriteString("[+]")
		case seg.IsIndex:
			fmt.Fprintf(&sb, "[%d]", seg.Index)
		default:
			if i > 0 {
				sb.WriteByte('.')
			}
			if seg.Key == "" || strings.ContainsAny(seg.Key, ".[]\"\\") {
				sb.WriteByte('"')
				sb.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(seg.Key))
				sb.WriteByte('"')
			} else {
				sb.WriteString(seg.Key)
			}
		}
	}
	return sb.String()
}

// Resolve walks path from root and returns the addressed node with aliases
// resolved. Append segments cannot be resolved.
func Resolve(root Node, path Path) (Node, error) {
	if root == nil {
		return nil, fmt.Errorf("document is empty")
	}
	cur := root.Target()
	for i, seg := range path {
		where := "document root"
		if i > 0 {
			where = path[:i].String()
		}
		switch {
		case seg.Append:
			return nil, fmt.Errorf("%s: [+] can only be used when setting a value", path.String())
		case seg.IsIndex:
			if cur.Kind() != Sequence {
				return nil, fmt.Errorf("%s is not a list, cannot index it with [%d]", where, seg.Index)
			}
			if seg.Index >= cur.Len() {
				return nil, fmt.Errorf("%s has %d item(s), index %d is out of range", where, cur.Len(), seg.Index)
			}
			cur = cur.Item(seg.Index).Target()
		default:
			if cur.Kind() != Mapping {
				return nil, fmt.Errorf("%s is not a mapping, cannot look up key %q", where, seg.Key)
			}
			next, ok := cur.Get(seg.Key)
			if !ok {
				return nil, fmt.Errorf("key %q not found in %s", seg.Key, where)
			}
			cur = next.Target()
		}
	}
	return cur, nil
}
