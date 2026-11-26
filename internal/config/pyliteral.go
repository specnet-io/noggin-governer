package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// noggin's config file is Python. We only need top-level `NAME = <literal>`
// assignments (strings, numbers, booleans, None, lists, tuples, dicts), so this
// is a small literal parser, not a Python interpreter. Anything else is skipped.

var assignRe = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*`)

// ParsePyConfig returns every top-level assignment whose value is a plain literal.
// Values are string, bool, nil, int64, float64, []any or map[string]any.
func ParsePyConfig(src string) map[string]any {
	out := map[string]any{}
	for _, m := range assignRe.FindAllStringSubmatchIndex(src, -1) {
		if m[1] < len(src) && src[m[1]] == '=' { // "X == y"
			continue
		}
		p := &pyParser{s: src, i: m[1]}
		v, err := p.value()
		if err != nil {
			continue
		}
		p.skipInline()
		if p.i < len(p.s) && p.s[p.i] != '\n' && p.s[p.i] != '\r' {
			continue // trailing expression (e.g. "A = 1 + 2"): not a literal
		}
		out[src[m[2]:m[3]]] = v
	}
	return out
}

type pyParser struct {
	s string
	i int
}

var errEOF = errors.New("unexpected end of input")

// skip whitespace, newlines and comments (valid between tokens inside brackets).
func (p *pyParser) skip() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.i++
		case c == '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case c == '\\' && p.i+1 < len(p.s) && p.s[p.i+1] == '\n':
			p.i += 2
		default:
			return
		}
	}
}

// skipInline skips spaces and a trailing comment on the current line only.
func (p *pyParser) skipInline() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
	if p.i < len(p.s) && p.s[p.i] == '#' {
		for p.i < len(p.s) && p.s[p.i] != '\n' {
			p.i++
		}
	}
}

func (p *pyParser) value() (any, error) {
	if p.i >= len(p.s) {
		return nil, errEOF
	}
	c := p.s[p.i]
	switch {
	case c == '[':
		return p.seq(']')
	case c == '(':
		return p.seq(')')
	case c == '{':
		return p.dict()
	case c == '"' || c == '\'':
		return p.strs()
	case strings.ContainsRune("rRuUbB", rune(c)) && p.i+1 < len(p.s) && (p.s[p.i+1] == '"' || p.s[p.i+1] == '\''):
		return p.strs()
	case c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9'):
		return p.number()
	}
	start := p.i
	for p.i < len(p.s) && (isIdent(p.s[p.i])) {
		p.i++
	}
	switch word := p.s[start:p.i]; word {
	case "True":
		return true, nil
	case "False":
		return false, nil
	case "None":
		return nil, nil
	default:
		return nil, fmt.Errorf("not a literal: %q", word)
	}
}

func isIdent(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (p *pyParser) seq(closer byte) (any, error) {
	p.i++ // opener
	items := []any{}
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, errEOF
		}
		if p.s[p.i] == closer {
			p.i++
			return items, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		items = append(items, v)
		p.skip()
		if p.i >= len(p.s) {
			return nil, errEOF
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case closer:
			p.i++
			return items, nil
		default:
			return nil, fmt.Errorf("unexpected %q in sequence", p.s[p.i])
		}
	}
}

func (p *pyParser) dict() (any, error) {
	p.i++ // {
	out := map[string]any{}
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, errEOF
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		k, err := p.value()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, errors.New("expected ':' in dict")
		}
		p.i++
		p.skip()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out[fmt.Sprint(k)] = v
		p.skip()
		if p.i >= len(p.s) {
			return nil, errEOF
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return nil, fmt.Errorf("unexpected %q in dict", p.s[p.i])
		}
	}
}

// strs parses one string literal plus any implicitly concatenated ones on the same line.
func (p *pyParser) strs() (any, error) {
	var b strings.Builder
	for {
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		b.WriteString(s)
		j := p.i
		for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t') {
			j++
		}
		if j < len(p.s) && (p.s[j] == '"' || p.s[j] == '\'' ||
			(strings.ContainsRune("rRuUbB", rune(p.s[j])) && j+1 < len(p.s) && (p.s[j+1] == '"' || p.s[j+1] == '\''))) {
			p.i = j
			continue
		}
		return b.String(), nil
	}
}

func (p *pyParser) str() (string, error) {
	raw := false
	for p.i < len(p.s) && strings.ContainsRune("rRuUbB", rune(p.s[p.i])) {
		if p.s[p.i] == 'r' || p.s[p.i] == 'R' {
			raw = true
		}
		p.i++
	}
	if p.i >= len(p.s) {
		return "", errEOF
	}
	q := p.s[p.i]
	triple := strings.HasPrefix(p.s[p.i:], strings.Repeat(string(q), 3))
	if triple {
		p.i += 3
	} else {
		p.i++
	}
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		if triple && strings.HasPrefix(p.s[p.i:], strings.Repeat(string(q), 3)) {
			p.i += 3
			return b.String(), nil
		}
		if !triple && c == q {
			p.i++
			return b.String(), nil
		}
		if !triple && c == '\n' {
			return "", errors.New("newline in string")
		}
		if c == '\\' && p.i+1 < len(p.s) {
			n := p.s[p.i+1]
			if raw {
				b.WriteByte(c)
				b.WriteByte(n)
				p.i += 2
				continue
			}
			p.i += 2
			switch n {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case '\\', '\'', '"':
				b.WriteByte(n)
			case '\n':
				// line continuation inside a string
			case 'x', 'u', 'U':
				width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[n]
				if p.i+width > len(p.s) {
					return "", errEOF
				}
				r, err := strconv.ParseUint(p.s[p.i:p.i+width], 16, 32)
				if err != nil {
					return "", err
				}
				b.WriteRune(rune(r))
				p.i += width
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			continue
		}
		b.WriteByte(c)
		p.i++
	}
	return "", errEOF
}

func (p *pyParser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' || p.s[p.i] == '+' {
		p.i++
	}
	for p.i < len(p.s) && strings.ContainsRune("0123456789abcdefABCDEFxXoO_.+-", rune(p.s[p.i])) {
		if (p.s[p.i] == '+' || p.s[p.i] == '-') && !(p.s[p.i-1] == 'e' || p.s[p.i-1] == 'E') {
			break
		}
		p.i++
	}
	tok := strings.ReplaceAll(p.s[start:p.i], "_", "")
	if n, err := strconv.ParseInt(tok, 0, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(tok, 64); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("bad number %q", tok)
}
