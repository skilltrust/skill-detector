package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// These generators describe selected constructs, not a shell interpreter.
// All paths and programs are inert text. Expectations follow operand roles
// assigned before rendering; no production matcher supplies the oracle.
func credentialPropertyPath(store, home byte) string {
	return []string{"~/", "$HOME/", "${HOME}/"}[int(home)%3] +
		[]string{".npmrc", ".codex/auth.json"}[int(store)%2]
}

func credentialPropertyCheck(t *testing.T, text, filename, ext, spelling string, line int, want bool) {
	t.Helper()
	findings := findRule(t, "SD-004").Match([]byte(text), model.FileContext{Path: filename, Ext: ext})
	if !want {
		if len(findings) != 0 {
			t.Fatalf("non-source flagged: %q: %+v", text, findings)
		}
		return
	}
	if len(findings) != 1 {
		t.Fatalf("source lost: %q: got %+v", text, findings)
	}
	f := findings[0]
	if f.FilePath != filename || f.Line != line || f.Description != "access to credential path "+spelling ||
		f.Severity != model.SeverityCritical || f.Axis != axes.PermissionHygiene {
		t.Fatalf("wrong source/location/classification: %q: %+v", text, f)
	}
}

// Move the candidate through every operand position: only the last operand
// is a destination. Add distinct innocuous sources to avoid symmetric cases.
// A suffix changes identity regardless of role; spacing/quoting does not.
func credentialPropertyCopy(t *testing.T, store, home, count, style byte, suffix bool) {
	t.Helper()
	path := credentialPropertyPath(store, home)
	candidate := path
	if suffix {
		candidate += ".example"
	}
	n := 2 + int(count)%9
	space := []string{" ", "\t", "  \t"}[int(style)%3]
	quote := []string{"", "\"", "'"}[int(style/3)%3]
	command := []string{"cp", "scp", "rsync"}[int(style/9)%3]
	prefix := []string{"", "Run ", "- ", "12. "}[int(style/27)%4]
	for position := 0; position < n; position++ {
		operands := make([]string, n)
		for i := range operands {
			operands[i] = fmt.Sprintf("./input-%d.txt", i)
			if i == position {
				operands[i] = candidate
			}
			operands[i] = quote + operands[i] + quote
		}
		text := prefix + command + space + strings.Join(operands, space)
		want := position < n-1 && !suffix
		credentialPropertyCheck(t, text, ".claude/hooks/check.sh", ".sh", path, 1, want)
	}
}

func TestSD004_PropertyCopyRoles(t *testing.T) {
	for store := byte(0); store < 2; store++ {
		for home := byte(0); home < 3; home++ {
			for style := byte(0); style < 108; style++ {
				for _, suffix := range []bool{false, true} {
					credentialPropertyCopy(t, store, home, style%9, style, suffix)
				}
			}
		}
	}
}

func FuzzSD004_PropertyCopyRoles(f *testing.F) {
	for _, seed := range []byte{0, 1, 8, 26, 53, 107, 255} {
		f.Add(seed, seed, seed, seed, false)
		f.Add(seed, seed, seed, seed, true)
	}
	f.Fuzz(credentialPropertyCopy)
}

// Encode equivalent JSON strings with independently chosen literal/escaped
// rune spellings, including surrogate pairs. Unmarshal validates the encoder's
// round trip, never computes the detection expectation.
func credentialPropertyJSON(text string, style byte) string {
	var out strings.Builder
	for i, r := range []rune(text) {
		if (i+int(style))%3 == 0 || style == 255 {
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
			} else {
				fmt.Fprintf(&out, "\\u%04x", r)
			}
		} else {
			encoded, _ := json.Marshal(string(r))
			out.Write(encoded[1 : len(encoded)-1])
		}
	}
	return out.String()
}

func credentialPropertyEncoding(t *testing.T, store, home, style, padding byte, source, suffix, crlf bool) {
	t.Helper()
	path := credentialPropertyPath(store, home)
	candidate := path
	if suffix {
		candidate += ".schema"
	}
	eol := "\n"
	if crlf {
		eol = "\r\n"
	}
	// The data prefix exercises backslashes, quotes, UTF-8 and surrogate pairs
	// before the source. It has no exemptions or credential-access vocabulary.
	prefix := "printf '%s' '" + strings.Repeat("a\\\"😀é", int(padding)%8) + "'; "
	if source {
		prefix += "cat \""
	} else {
		prefix += "grep -F -e \""
	}
	tail := "\""
	if !source {
		tail += " README.md"
	}
	command := prefix + candidate + tail
	want := source && !suffix
	physicalPadding := strings.Repeat(eol, int(padding)%4)
	credentialPropertyCheck(t, physicalPadding+command+eol, ".claude/hooks/check.sh", ".sh", path, int(padding)%4+1, want)
	// Encode segments separately so the expected physical byte offset is
	// derived directly from the rendered prefix, even when the path is escaped.
	encodedPrefix := credentialPropertyJSON(prefix, style)
	encoded := encodedPrefix + credentialPropertyJSON(candidate+tail, style)
	var decoded string
	if err := json.Unmarshal([]byte("\""+encoded+"\""), &decoded); err != nil || decoded != command {
		t.Fatalf("generator produced invalid JSON: %q: %v", encoded, err)
	}
	jsonLinePrefix := `  "command": "`
	document := "{" + eol + physicalPadding + jsonLinePrefix + encoded + "\"" + eol + "}"
	credentialPropertyCheck(t, document, ".claude/settings.json", ".json", path, int(padding)%4+2, want)
	if want {
		// Public findings expose lines, not columns. Check the internal offset
		// as well: it controls the established negation-before-access exemption.
		canonical := "~/" + []string{".npmrc", ".codex/auth.json"}[int(store)%2]
		for _, entry := range credentialPathSpellings {
			if string(entry.canonical) == canonical {
				idx, spelling := entry.findJSONContentAccess([]byte(jsonLinePrefix + encoded + "\""))
				if idx != len(jsonLinePrefix)+len(encodedPrefix) || string(spelling) != path {
					t.Fatalf("wrong encoded offset: got %d/%q, want %d/%q; %s", idx, spelling, len(jsonLinePrefix)+len(encodedPrefix), path, document)
				}
				return
			}
		}
		t.Fatalf("missing entry %s", canonical)
	}
}

func TestSD004_PropertyJSONEncoding(t *testing.T) {
	for store := byte(0); store < 2; store++ {
		for home := byte(0); home < 3; home++ {
			for _, style := range []byte{0, 1, 2, 255} {
				for padding := byte(0); padding < 8; padding++ {
					for _, source := range []bool{false, true} {
						for _, suffix := range []bool{false, true} {
							for _, crlf := range []bool{false, true} {
								credentialPropertyEncoding(t, store, home, style, padding, source, suffix, crlf)
							}
						}
					}
				}
			}
		}
	}
}

func FuzzSD004_PropertyJSONEncoding(f *testing.F) {
	for _, seed := range []byte{0, 1, 2, 7, 255} {
		f.Add(seed, seed, seed, seed, true, false, false)
		f.Add(seed, seed, seed, seed, false, false, true)
		f.Add(seed, seed, seed, seed, true, true, true)
	}
	f.Fuzz(credentialPropertyEncoding)
}
