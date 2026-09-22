package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// Path traversal detection patterns.
var (
	rePathTraversal = regexp.MustCompile(`\.\.\/`)
	reAbsolutePath  = regexp.MustCompile(`(?:^|[\s"'=:])(/etc/|/home/|/root/|/var/|/tmp/|/usr/|/opt/)`)
	reWindowsPath   = regexp.MustCompile(`(?i)(?:^|[\s"'=:])[A-Z]:\\`)
	reURLScheme     = regexp.MustCompile(`://`)
	reFullPath      = regexp.MustCompile(`(/(?:etc|home|root|var|tmp|usr|opt)/[^\s"')\]>,;|&#${}` + "`" + `]*)`)
)

// reNegatedGuidance matches prohibition phrasing. When it precedes a
// sensitive-path mention on the same line, the line is security guidance,
// not an access attempt. This damping is a deliberate trade: it accepts a
// narrow, contrived miss class in exchange for removing a guaranteed
// false-positive class, and the layered mitigation is rule co-occurrence plus
// triage. The shape is deliberate — narrowing or widening it needs the
// maintainer's sign-off.
var reNegatedGuidance = regexp.MustCompile(`(?i)\b(never|do\s+not|don'?t|avoid|must\s+not|not\s+allowed|forbidden|refuse\s+to)\b`)

// reDocumentaryContext matches lines that are documentation *about* sensitive
// paths rather than instructions to touch them: Markdown table rows and
// interrogative bullets, the shapes threat-model documentation is written in.
// Shape alone is NOT sufficient evidence that a line is documentation, so
// callers MUST also consult a shell-invocation test and skip the damping when
// it matches. Which test depends on the caller: credentialAccessRule uses
// invokesCommandOnCredentialLine (reShellInvocation plus the file readers),
// persistenceRule in integrity.go uses reShellInvocation alone. They are
// deliberately not the same predicate — see reCredentialFileReader. This
// regex must never be used as a standalone exemption, and the pairing must
// not be changed without the maintainer's sign-off.
var reDocumentaryContext = regexp.MustCompile(`(?i)^\s*(\|.*\|\s*$|[-*]\s+(could|does|would|should|can|is|are|might|may)\b.*\?\s*$)`)

// reShellInvocation matches imperative shell-command tokens (as standalone
// words followed by an argument) or shell metacharacters that indicate an
// executable command is present, even inside a documentary-shaped line.
// Vetoes reDocumentaryContext: a table row or interrogative bullet that
// contains a real command is not documentation, regardless of its shape.
//
// Deliberately does NOT veto on a bare backtick: Markdown code spans wrap
// paths in documentation near-universally (a code span reading ~/.ssh/),
// and a code span containing only a path is not an invocation. A
// backtick-wrapped command (a code span reading cat ~/.ssh/id_rsa) still
// vetoes because its content independently matches the imperative-token
// branch below — the backtick characters themselves carry no signal, only
// the text they wrap does.
//
// The single-`>` branch requires a redirect-shaped target (`~`, `./`, `/`,
// `$VAR`) and excludes a preceding `-`, so a Markdown arrow ("writes to
// .zshrc -> persistence") does not veto — `>>` (append) still vetoes
// unconditionally since it has no legitimate non-shell reading in prose.
//
// THIS REGEX IS SHARED. It vetoes reDocumentaryContext here in
// credentialAccessRule (SD-004) *and* in persistenceRule's shell-profile
// branch (SD-013, integrity.go). Widening it therefore changes an unrelated
// rule's output, in the direction of more findings. Do not add verbs here to
// fix an SD-004 problem — see reCredentialFileReader below, which exists
// precisely because that was tried and broke SD-013.
var reShellInvocation = regexp.MustCompile(`(?i)\b(cat|cp|mv|rm|scp|rsync|curl|wget|nc|dd|tar|base64|openssl|eval|exec|source|sh|bash|zsh|chmod|chown|python3?|perl|ruby|node)\b\s+\S|\$\(|>>|(?:^|[^-])>\s*[~./$]`)

// reCredentialFileReader matches the read-and-inspect verbs that
// reShellInvocation's copy/move/fetch list omits. It is consulted ONLY by
// credentialAccessRule, through invokesCommandOnCredentialLine.
//
// Why it is a separate regex rather than more verbs in reShellInvocation:
// the final whole-branch review found that a documentary bullet reading a
// credential kept its exemption —
// `- app.credentials: use head -c 4096 ~/.credentials to read the token`
// graded permission_hygiene A — and the obvious fix was to widen
// reShellInvocation. That shipped, and the re-review caught what it did to
// SD-013: reShellInvocation is also the veto on persistenceRule's
// documentary damping, so ordinary threat-model questions started firing a
// CRITICAL persistence finding.
//
//   - Could it read .zshrc with grep to check settings?   -> SD-013 CRITICAL
//   - Could it open .bashrc to check settings?            -> SD-013 CRITICAL
//   - Does it use awk on .zshrc for parsing?              -> SD-013 CRITICAL
//
// All three are clean on either side of that mistake, and
// TestSD013_ReaderVerbsInInterrogativeBulletNotFlagged pins them. Keeping
// the two lists apart is what makes an SD-004 widening cost nothing
// anywhere else. reShellInvocation's own verb set must stay byte-identical
// to what SD-013 was measured against.
//
// `ssh` was on the review's list and is deliberately NOT here either. This
// regex is matched case-insensitively against prose, and `\bSSH\b\s+\S`
// matches the ordinary honest line `# Add ~/.ssh/id_ed25519.pub to
// GitHub Settings -> SSH Keys` on the words "SSH Keys" — which, since
// allSSHPathsArePublic is vetoed through this path, would re-flag the exact
// benign shape that exemption exists for (TestSD004_SSHPublicKeyNotFlagged).
// `ssh` as a remote-exec verb is worth less than that costs; `scp` and
// `rsync` already cover the file-transfer half of it.
var reCredentialFileReader = regexp.MustCompile(`(?i)\b(head|tail|less|awk|sed|grep|xxd|strings|od|open|pbcopy|env|printenv)\b\s+\S`)

// invokesCommandOnCredentialLine reports whether the line runs a command, for
// the purpose of vetoing one of credentialAccessRule's three exemptions. It
// is the widened test — reShellInvocation plus the file readers — and is
// deliberately the only caller of reCredentialFileReader, so that no other
// rule inherits the widening.
func invokesCommandOnCredentialLine(line []byte) bool {
	return reShellInvocation.Match(line) || reCredentialFileReader.Match(line)
}

// Credential path patterns as literal byte slices. Entries rooted at `~/` are
// matched in every spelling in homePrefixes (see credentialPathSpellings
// below); the rest are matched literally. Match()'s two PATTERN-KEYED
// exemptions — the `.credentials` import/field-doc carve-outs and the
// `~/.ssh/` `.pub` carve-out — key on the entry as written here, never on
// the spelling found, so a new spelling can never detach either of them from
// the path it guards. reNegatedGuidance is different: it is a POSITION test
// against the offset find() returns, so it is spelling-aware by
// construction — the offset it compares against has to be the leftmost
// occurrence of the entry in ANY spelling for that test to ask the right
// question, which is what find()'s doc comment explains.
var credentialPaths = [][]byte{
	[]byte("~/.aws/"),
	[]byte("~/.ssh/"),
	[]byte("~/.gnupg/"),
	[]byte("~/.env"),
	[]byte("/etc/shadow"),
	[]byte("/etc/passwd"),
	[]byte(".credentials"),
	[]byte("~/.npmrc"),
	[]byte("~/.codex/auth.json"),
}

// These two file targets require content-access evidence, unlike the legacy
// path patterns above. npmrc also holds ordinary registry configuration;
// mentioning either filename or changing its permissions is not a read.
// Keep this separate from the shared exemption vetoes: changing those would
// change established SD-004/SD-013 behaviour. This is a line-local detector,
// not shell parsing or cross-line variable/data-flow analysis.
const proseAccessPrefix = `\b(?:read|print|dump|show|display|return|include|send|upload|copy|disclose|paste|output)\s+(?:(?:the|its|full|complete|entire|raw|file|contents?|of|from)\s+)*`

const credentialContentPrefix = `(?i:` + proseAccessPrefix + "[`\"']?" +
	`|\b(?:cat|head|tail|less|more|awk|sed|grep|xxd|strings|od|base64|jq)\s+(?:[^;|&>\r\n]*?` + "[ \t\"'`(<:=|]" + `)?` +
	`|\b(?:cp|scp|rsync)\s+(?:-[^\s]+\s+)*["']?` +
	`|<\s*["']?)`

const credentialContentBoundary = `(?:$|[ \t"'` + "`" + `)>,;|&\]}!?]|\.(?:$|[ \t])|\\")`

type credentialCommandRegion struct {
	text              []byte
	offsets           []int
	literals, sources [][2]int
	language          bool
}

type credentialCommandBody struct {
	span     [2]int
	language bool
}

func credentialMarkdownPath(text []byte) bool {
	if bytes.ContainsAny(text, " \t\r\n<>;|&()") {
		return false
	}
	for _, prefix := range homePrefixes {
		if bytes.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// Partition once, not once per nesting level. A parent receives a non-path
// placeholder for each substitution; its body belongs only to the child.
// Total text and offset storage is O(n), even for adversarial nesting.
func credentialCommandRegions(line []byte, language bool) []credentialCommandRegion {
	expressions := reCredentialReadExpression.FindAllSubmatchIndex(line, -1)
	if !language && len(expressions) > 0 && reCredentialReadCodeStart.Match(line) {
		// A printed example cannot turn an enclosing shell assignment into
		// source code. Require an actual unquoted expression before promoting.
		quote, candidate := byte(0), 0
		for i := 0; i < len(line) && candidate < len(expressions); i++ {
			for candidate < len(expressions) && expressions[candidate][0] < i {
				candidate++
			}
			if candidate < len(expressions) && expressions[candidate][0] == i && quote == 0 {
				language = true
				break
			}
			c := line[i]
			if quote == 0 && c == '#' {
				break // Comment instructions cannot reclassify preceding shell code.
			}
			if c == '\\' && quote != '\'' {
				i++
			} else if quote != 0 && c == quote {
				quote = 0
			} else if quote == 0 && (c == '\'' || c == '"') {
				quote = c
			}
		}
	}
	regions := []credentialCommandRegion{{language: language}}
	type frame struct {
		region, opening, parens                int
		closing, quote                         byte
		child, language                        bool
		literalStart, readStart                int
		literalRead, literalFile, readEligible bool
	}
	stack := []frame{{language: language, readStart: -1}}
	expression := 0
	proseExpressions := reCredentialProseFile.FindAllSubmatchIndex(line, -1)
	proseExpression := 0
	proseContext := line
	if len(proseExpressions) > 0 {
		// Operand words such as jq variable names and echo arguments are
		// not prose introductions, regardless of their spelling.
		proseContext, _, _, _ = maskCredentialCommandData(line)
	}
	put := func(region, pos int, c byte) {
		regions[region].text = append(regions[region].text, c)
		regions[region].offsets = append(regions[region].offsets, pos)
	}
	for i := 0; i < len(line); i++ {
		f := &stack[len(stack)-1]
		c := line[i]
		for expression < len(expressions) && expressions[expression][0] < i {
			expression++
		}
		if expression < len(expressions) && expressions[expression][0] == i && f.quote == 0 {
			f.language = true
			f.readEligible = true
			f.readStart = expressions[expression][2]
			if f.readStart < 0 {
				f.readStart = expressions[expression][4]
			}
		}
		for proseExpression < len(proseExpressions) && proseExpressions[proseExpression][0] < i {
			proseExpression++
		}
		if proseExpression < len(proseExpressions) && proseExpressions[proseExpression][0] == i &&
			f.quote == 0 && !f.language && proseContext[i] != ' ' {
			f.readStart = proseExpressions[proseExpression][2]
			tail := line[proseExpressions[proseExpression][3]:]
			f.readEligible = len(tail) == 0 || bytes.ContainsAny(tail[:1], " \t\r\n),;|&<>}]!?") ||
				(tail[0] == '.' && (len(tail) == 1 || tail[1] == ' ' || tail[1] == '\t'))
		}
		if c == '\\' && (f.quote != '\'' || f.language) {
			put(f.region, i, c)
			if i+1 < len(line) {
				i++
				put(f.region, i, line[i])
			}
			continue
		}
		if c == f.closing && f.quote == 0 && f.parens == 0 && len(stack) > 1 {
			// A one-token Markdown code span is often a path, not a
			// command. Keep it with its surrounding imperative prose.
			if c == '`' && !f.child && credentialMarkdownPath(regions[f.region].text) {
				parent := &regions[stack[len(stack)-2].region]
				parent.text = parent.text[:len(parent.text)-1]
				parent.offsets = parent.offsets[:len(parent.offsets)-1]
				for pos := f.opening + 1; pos < i; pos++ {
					put(stack[len(stack)-2].region, pos, line[pos])
				}
				if i+1 < len(line) && strings.ContainsRune(".!?,", rune(line[i+1])) &&
					(i+2 == len(line) || line[i+2] == ' ' || line[i+2] == '\t') {
					// Sentence punctuation outside a Markdown span is not
					// part of its filename. Keep ordinary shell suffixes intact.
					put(stack[len(stack)-2].region, i, ' ')
				}
				regions[f.region] = credentialCommandRegion{}
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if !f.language && !f.literalFile && f.quote != '\'' && (c == '`' || (c == '$' && i+1 < len(line) && line[i+1] == '(')) {
			closing := byte('`')
			opening := i
			if c == '$' {
				closing = ')'
				i++
			}
			put(f.region, opening, 0) // Cannot synthesize part of a path.
			f.child = true
			regions = append(regions, credentialCommandRegion{})
			stack = append(stack, frame{region: len(regions) - 1, opening: opening, closing: closing, readStart: -1})
			continue
		}
		put(f.region, i, c)
		if f.quote != 0 && c == f.quote {
			if f.language || f.literalFile {
				span := [2]int{f.literalStart, len(regions[f.region].text)}
				regions[f.region].literals = append(regions[f.region].literals, span)
				if f.literalRead {
					regions[f.region].sources = append(regions[f.region].sources, span)
				}
			}
			f.quote = 0
			f.literalRead = false
			f.literalFile = false
		} else if f.quote == 0 && (c == '\'' || c == '"' || (f.language && c == '`')) {
			f.quote = c
			f.literalStart = len(regions[f.region].text) - 1
			f.literalFile = i == f.readStart
			f.literalRead = f.literalFile && f.readEligible
		} else if f.quote == 0 && c == ';' {
			f.language = regions[f.region].language
		} else if f.quote == 0 && c == '(' {
			f.parens++
		} else if f.quote == 0 && c == ')' && f.parens > 0 {
			f.parens--
		}
	}
	return regions
}

// Regions contain no executable child bodies; only quote-aware word
// boundaries are needed to classify command operands here.
func credentialCommandTokens(line []byte) [][2]int {
	var tokens [][2]int
	start, quote := -1, byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		separator := strings.ContainsRune(";|&<>`", rune(c))
		if quote == 0 && (c == ' ' || c == '\t' || c == '\r' || c == '\n' || (separator && c != '`')) {
			if start >= 0 {
				tokens = append(tokens, [2]int{start, i})
				start = -1
			}
			if separator {
				end := i + 1
				if c == '<' && bytes.HasPrefix(line[i:], []byte("<<<")) {
					end = i + 3
				}
				tokens = append(tokens, [2]int{i, end})
				i = end - 1
			}
			continue
		}
		if start < 0 {
			start = i
		}
		if c == '\\' && quote != '\'' {
			i++
		} else if c == quote {
			quote = 0
		} else if quote == 0 && (c == '\'' || c == '"') {
			quote = c
		}
	}
	if start >= 0 {
		tokens = append(tokens, [2]int{start, len(line)})
	}
	return tokens
}

const quotedPathLiteral = `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`

var reCredentialListMarker = regexp.MustCompile(`^(?:[-+*]|[0-9]{1,9}[.)])$`)
var reCredentialQuotedLiteral = regexp.MustCompile(quotedPathLiteral)
var reCredentialProseFile = regexp.MustCompile(`(?i)` + proseAccessPrefix + `(` + quotedPathLiteral + `)`)
var reCredentialReadExpression = regexp.MustCompile(
	`\b(?:readFileSync|readFile)\s*\(\s*(` + quotedPathLiteral + `)\s*[,)]|` +
		`\b(?:open|Path)\s*\(\s*(` + quotedPathLiteral + `)\s*\)\s*\.(?:read|read_text|read_bytes)\s*\(`,
)
var reCredentialReadCodeStart = regexp.MustCompile(`^\s*(?:[a-zA-Z_$][\w.$]*\s*[=(]|(?:const|let|var|return|await)\b)`)
var reCredentialAwkRead = regexp.MustCompile(`^getline\b\s*(?:[a-zA-Z_]\w*\s*)?<\s*("[^"\\\n]*")\s*(?:[;})\]]|$)`)
var reCredentialAwkExecute = regexp.MustCompile(`^system\s*\(\s*"([^"\\\n]*)"\s*\)`)
var reCredentialAwkAssignment = regexp.MustCompile(`^[a-zA-Z_]\w*=`)

// Locate a selected sed operation at a command boundary, never inside an
// address, substitution or text argument. r/R/e consume the rest of the line.
func credentialSedOperation(program []byte) (byte, int) {
	i := 0
	skipDelimited := func(delimiter byte) bool {
		for i < len(program) {
			c := program[i]
			i++
			if c == '\\' && i < len(program) {
				i++
			} else if c == delimiter {
				return true
			}
		}
		return false
	}
	for i < len(program) {
		if strings.ContainsRune(" \t;{},!$0123456789", rune(program[i])) {
			i++
			continue
		}
		command := program[i]
		i++
		if command == '/' {
			if !skipDelimited('/') {
				break
			}
			continue
		}
		switch command {
		case 'r', 'R', 'e':
			if i < len(program) && (program[i] == ' ' || program[i] == '\t') {
				for i < len(program) && (program[i] == ' ' || program[i] == '\t') {
					i++
				}
				return command, i
			}
			return 0, 0
		case 's', 'y':
			if i == len(program) {
				return 0, 0
			}
			delimiter := program[i]
			i++
			for range 2 { // Pattern, then replacement.
				if !skipDelimited(delimiter) {
					return 0, 0
				}
			}
		case '#', 'a', 'i', 'c', 'w', 'W':
			return 0, 0 // Remaining text is a comment, data or output filename.
		}
		for i < len(program) && program[i] != ';' {
			if program[i] == '#' || (command == 's' && program[i] == 'w') {
				return 0, 0 // Substitution output filenames also extend to line end.
			}
			i++
		}
	}
	return 0, 0
}

// Return masked text, quoted file operands, raw filenames and literal execute
// bodies separately. The caller partitions execute bodies before scanning.
func maskCredentialCommandData(line []byte) ([]byte, [][2]int, [][2]int, []credentialCommandBody) {
	out := bytes.Clone(line)
	readExpression := reCredentialReadExpression.Match(line)
	mask := func(start, end int) {
		for i := start; i < end; i++ {
			out[i] = ' '
		}
	}
	active, pattern, options := false, false, true
	commandStart, jq, literalArgs := true, false, false
	proseCommand := false
	fileReader := ""
	xxdInput, xxdOptionValue := false, false
	var redirect byte
	jqDataWords, jqFileWords := 0, 0
	jqNeedsFilter := false
	var fileSources, rawSources [][2]int
	var executions []credentialCommandBody
	languageCommand, languageNext := "", false
	scriptCommand, scriptNeedsProgram, scriptNext := "", false, byte(0)
	maskProgram := func(start, end int) {
		mask(start, end)
		if end-start >= 2 && (line[start] == '\'' || line[start] == '"') && line[end-1] == line[start] {
			start++
			end--
		}
		if scriptCommand == "sed" {
			command, offset := credentialSedOperation(line[start:end])
			if command == 'e' {
				executions = append(executions, credentialCommandBody{span: [2]int{start + offset, end}})
			} else if command != 0 {
				rawSources = append(rawSources, [2]int{start + offset, end})
			}
			return
		}
		// Only code tokens supply AWK operations. Selected literal arguments
		// contain no escapes; undecoded AWK bytes must not become shell code.
		for i := start; i < end; {
			if line[i] == '#' {
				return
			}
			if line[i] == '"' {
				i++
				for i < end {
					c := line[i]
					i++
					if c == '\\' && i < end {
						i++
					} else if c == '"' {
						break
					}
				}
				continue
			}
			var loc []int
			if i == start || !strings.ContainsRune("_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", rune(line[i-1])) {
				switch line[i] {
				case 'g':
					loc = reCredentialAwkRead.FindSubmatchIndex(line[i:end])
				case 's':
					loc = reCredentialAwkExecute.FindSubmatchIndex(line[i:end])
				}
			}
			if loc == nil {
				i++
				continue
			}
			if line[i] == 'g' {
				fileSources = append(fileSources, [2]int{i + loc[2], i + loc[3]})
			} else {
				executions = append(executions, credentialCommandBody{span: [2]int{i + loc[2], i + loc[3]}})
			}
			i += loc[1]
		}
	}
	copyCommand := false
	var copyOperands, grepOperands [][2]int
	finish := func() {
		if active {
			for i, loc := range grepOperands {
				if pattern || i > 0 {
					fileSources = append(fileSources, loc)
				}
				mask(loc[0], loc[1])
			}
		}
		if copyCommand && len(copyOperands) >= 2 {
			fileSources = append(fileSources, copyOperands[:len(copyOperands)-1]...)
			for _, loc := range copyOperands {
				mask(loc[0], loc[1])
			}
		}
	}
	var next byte
	tokens := credentialCommandTokens(line)
	for i, loc := range tokens {
		word := string(line[loc[0]:loc[1]])
		if i == 0 && loc[1] < len(line) && (line[loc[1]] == ' ' || line[loc[1]] == '\t') && reCredentialListMarker.MatchString(word) {
			proseCommand = true
			continue
		}
		if proseCommand && i == len(tokens)-1 && len(word) > 1 && strings.ContainsRune(".!?", rune(word[len(word)-1])) {
			loc[1]-- // Sentence punctuation outside the final filename token.
			word = word[:len(word)-1]
		}
		if strings.HasPrefix(word, "#") {
			// Shell comments remain instruction text, but do not inherit the
			// preceding command's argument roles or access evidence.
			finish()
			active, jq, literalArgs = false, false, false
			fileReader = ""
			scriptCommand = ""
			languageCommand, languageNext = "", false
			copyCommand, copyOperands = false, nil
			proseCommand = false
			commandStart, redirect = true, 0
			out[loc[0]] = ';'
			loc[0]++
			word = word[1:]
			if word == "" {
				continue
			}
		}
		// An unquoted number touching a redirection is a descriptor, not an
		// operand (unlike the separate argument in "grep 2 > output.txt").
		if redirect == 0 && strings.Trim(word, "0123456789") == "" && i+1 < len(tokens) &&
			tokens[i+1][0] == loc[1] && strings.ContainsRune("<>", rune(line[loc[1]])) {
			mask(loc[0], loc[1])
			continue
		}
		if word == "<<<" {
			redirect = 'h' // Here-string data, not a filename.
			mask(loc[0], loc[1])
			continue
		}
		if word == ">" && loc[0] > 0 && line[loc[0]-1] == '=' && readExpression &&
			!active && !jq && !literalArgs && fileReader == "" && scriptCommand == "" && languageCommand == "" && !copyCommand {
			continue // Callback arrow in a read expression, not a shell destination.
		}
		if len(word) == 1 && strings.ContainsAny(word, ";|&<>`") {
			if strings.ContainsAny(word, "<>") {
				redirect = word[0]
				if redirect == '>' {
					mask(loc[0], loc[1])
				}
			} else {
				finish()
				active, jq, literalArgs = false, false, false
				fileReader = ""
				scriptCommand = ""
				languageCommand, languageNext = "", false
				copyCommand, copyOperands = false, nil
				proseCommand = false
				commandStart, redirect = true, 0
			}
			continue
		}
		if redirect != 0 {
			// Output destinations neither read a credential nor terminate the
			// command's input operands. Input redirections remain evidence.
			if redirect == '<' {
				fileSources = append(fileSources, loc)
			}
			mask(loc[0], loc[1])
			redirect = 0
			continue
		}
		if commandStart || (!active && !jq && !literalArgs && fileReader == "" && scriptCommand == "" && languageCommand == "" && !copyCommand) {
			// Explicit imperative introductions do not own the following
			// command's operands. Never recognize these inside an operand list.
			if strings.EqualFold(word, "run") || strings.EqualFold(word, "please") {
				proseCommand = true
				continue
			}
			proseCommand = proseCommand || !commandStart
			commandStart = false
			if strings.EqualFold(word, "grep") {
				active, pattern, options, next = true, false, true, 0
				grepOperands = nil
			} else if strings.EqualFold(word, "jq") {
				jq, options, jqDataWords, jqFileWords = true, true, 0, 0
				jqNeedsFilter = true
			} else if strings.EqualFold(word, "echo") || strings.EqualFold(word, "printf") {
				literalArgs = true
			} else if strings.EqualFold(word, "cp") || strings.EqualFold(word, "scp") || strings.EqualFold(word, "rsync") {
				copyCommand, options, copyOperands = true, true, nil
			} else if strings.EqualFold(word, "sed") || strings.EqualFold(word, "awk") {
				scriptCommand, scriptNeedsProgram, scriptNext, options = strings.ToLower(word), true, 0, true
				mask(loc[0], loc[1]) // The program's selected operations supply evidence.
			}
			switch strings.ToLower(word) {
			case "cat", "head", "tail", "less", "more", "xxd", "strings", "od", "base64":
				fileReader = strings.ToLower(word)
				xxdInput, xxdOptionValue = false, false
			case "stat", "ls", "test", "chmod", "touch", "basename", "dirname":
				literalArgs = true
			case "node", "nodejs", "python", "python3":
				languageCommand = strings.ToLower(word)
			}
			continue
		}
		if languageCommand != "" {
			if languageNext {
				start, end := loc[0], loc[1]
				if end-start >= 2 && (line[start] == '\'' || line[start] == '"') && line[end-1] == line[start] {
					start++
					end--
				}
				executions = append(executions, credentialCommandBody{span: [2]int{start, end}, language: true})
				languageNext = false
			} else if strings.HasPrefix(languageCommand, "node") {
				languageNext = word == "-e" || word == "--eval" || word == "-p" || word == "--print"
			} else {
				languageNext = word == "-c"
			}
			mask(loc[0], loc[1])
			continue
		}
		if fileReader != "" {
			if fileReader != "xxd" {
				fileSources = append(fileSources, loc)
			} else if xxdOptionValue {
				xxdOptionValue = false
			} else if strings.HasPrefix(word, "-") && word != "-" {
				switch word {
				case "-c", "-cols", "-g", "-groupsize", "-l", "-len", "-s", "-seek", "-o", "-offset", "-n", "-name", "-R":
					xxdOptionValue = true
				}
			} else if !xxdInput {
				fileSources = append(fileSources, loc)
				xxdInput = true
			}
			mask(loc[0], loc[1])
			continue
		}
		if scriptCommand != "" {
			if scriptNext != 0 {
				switch scriptNext {
				case 'e':
					maskProgram(loc[0], loc[1])
				case 'v':
					mask(loc[0], loc[1])
				case 'f':
					fileSources = append(fileSources, loc)
					mask(loc[0], loc[1])
				}
				scriptNext = 0
			} else if options && word == "--" {
				options = false
			} else if options && strings.HasPrefix(word, "-") && word != "-" {
				kind, attached := byte(0), -1
				if strings.HasPrefix(word, "--") {
					name, _, hasValue := strings.Cut(word, "=")
					switch name {
					case "--expression", "--source":
						kind = 'e'
					case "--file":
						kind = 'f'
					case "--assign", "--field-separator":
						kind = 'v'
					}
					if hasValue {
						attached = loc[0] + len(name) + 1
					}
				} else {
					for j := 1; j < len(word); j++ {
						if !strings.ContainsRune("efvF", rune(word[j])) {
							continue
						}
						kind = word[j]
						if kind == 'F' {
							kind = 'v'
						}
						if j+1 < len(word) {
							attached = loc[0] + j + 1
						}
						break
					}
				}
				if kind != 0 {
					if kind == 'e' || kind == 'f' {
						scriptNeedsProgram = false
					}
					if attached < 0 {
						scriptNext = kind
					} else {
						switch kind {
						case 'e':
							maskProgram(attached, loc[1])
						case 'f':
							fileSources = append(fileSources, [2]int{attached, loc[1]})
							mask(attached, loc[1])
						case 'v':
							mask(attached, loc[1])
						}
					}
				}
			} else if scriptNeedsProgram {
				maskProgram(loc[0], loc[1])
				scriptNeedsProgram = false
			} else {
				if scriptCommand != "awk" || !reCredentialAwkAssignment.MatchString(word) {
					fileSources = append(fileSources, loc)
				}
				mask(loc[0], loc[1])
			}
			continue
		}
		if copyCommand {
			if options && word == "--" {
				options = false
			} else if options && strings.HasPrefix(word, "-") && word != "-" {
				// Only argument-free flags have ordinary source/destination
				// semantics. Leave other forms to the existing copy matcher.
				if strings.Trim(word[1:], "rRpav") != "" {
					copyCommand, copyOperands = false, nil
				}
			} else {
				copyOperands = append(copyOperands, loc)
			}
			continue
		}
		if literalArgs {
			// Printed words are data, even when they name a reader. Executable
			// substitutions were partitioned into independent child regions.
			mask(loc[0], loc[1])
			continue
		}
		if jq {
			if jqDataWords > 0 {
				mask(loc[0], loc[1])
				jqDataWords--
			} else if jqFileWords > 0 {
				if jqFileWords == 1 {
					fileSources = append(fileSources, loc)
				}
				mask(loc[0], loc[1])
				jqFileWords-- // File-option operands cannot introduce data options.
			} else if options && word == "--" {
				options = false
			} else if options && strings.HasPrefix(word, "-") && word != "-" {
				switch word {
				case "--arg", "--argjson":
					jqDataWords = 2 // Variable name and literal value, not file inputs.
				case "--indent":
					jqDataWords = 1
				case "--rawfile", "--slurpfile", "--argfile":
					jqFileWords = 2
				case "-f", "--from-file":
					jqFileWords, jqNeedsFilter = 1, false
				case "-L":
					jqDataWords = 1 // Module search directory, not a file read.
				default:
					// Short flags can be combined, e.g. -cf filter.jq. An
					// attached -L directory is not a group of option letters.
					if strings.HasPrefix(word, "-L") {
						mask(loc[0], loc[1])
					} else if !strings.HasPrefix(word, "--") && strings.ContainsRune(word, 'f') {
						jqFileWords, jqNeedsFilter = 1, false
					}
				}
			} else if jqNeedsFilter {
				// The first positional argument is code, not an input filename.
				// Shell substitutions inside it remain independent regions.
				mask(loc[0], loc[1])
				jqNeedsFilter = false
			} else {
				fileSources = append(fileSources, loc)
				mask(loc[0], loc[1])
			}
			continue
		}
		if !active {
			continue
		}
		if next != 0 {
			if next == 'f' {
				fileSources = append(fileSources, loc)
			}
			mask(loc[0], loc[1])
			next = 0
			continue
		}
		if options && word == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "--") {
			name, _, attached := strings.Cut(word, "=")
			kind := byte('v')
			switch name {
			case "--regexp":
				kind, pattern = 'e', true
			case "--file":
				kind, pattern = 'f', true
			case "--after-context", "--before-context", "--context", "--max-count", "--directories", "--devices", "--label", "--include", "--exclude", "--exclude-dir", "--binary-files":
			default:
				mask(loc[0], loc[1])
				continue
			}
			if attached && (kind == 'e' || kind == 'f') {
				if kind == 'f' {
					fileSources = append(fileSources, [2]int{loc[0] + len(name) + 1, loc[1]})
				}
			}
			mask(loc[0], loc[1])
			if !attached {
				next = kind
			}
			continue
		}
		if options && strings.HasPrefix(word, "-") && word != "-" {
			end := loc[1]
			for i := 1; i < len(word); i++ {
				kind := word[i]
				if !strings.ContainsRune("efABCDdm", rune(kind)) {
					continue
				}
				if kind == 'e' || kind == 'f' {
					pattern = true
				}
				if i+1 == len(word) {
					next = kind
				} else if kind == 'e' || kind == 'f' {
					end = loc[0] + i + 1
					if kind == 'f' {
						fileSources = append(fileSources, [2]int{end, loc[1]})
					}
					mask(end, loc[1])
				}
				break
			}
			mask(loc[0], end)
			continue
		}
		grepOperands = append(grepOperands, loc)
	}
	finish()
	return out, fileSources, rawSources, executions
}

// Decode JSON strings independently so a command's quoting is shell quoting,
// not JSON quoting, and unrelated fields cannot supply its access verb. Map
// the matched offset back for the existing line-local negation position test.
func (e credentialPathSpelling) findJSONContentAccess(line []byte) (int, []byte) {
	// Without escapes, decoding cannot introduce a missing path spelling.
	// Escaped strings still need decoding before this check is conclusive.
	if !bytes.ContainsRune(line, '\\') {
		if idx, _ := e.find(line); idx < 0 {
			return -1, nil
		}
	}
	for cursor := 0; cursor < len(line); {
		start := bytes.IndexByte(line[cursor:], '"')
		if start < 0 {
			break
		}
		start += cursor
		end := start + 1
		for end < len(line) && line[end] != '"' {
			if line[end] == '\\' {
				end++ // An escaped quote cannot terminate this string.
			}
			end++
		}
		if end >= len(line) {
			break
		}
		cursor = end + 1
		raw := line[start:cursor]
		var decoded string
		if json.Unmarshal(raw, &decoded) != nil {
			continue
		}
		idx, spelling := -1, []byte(nil)
		for offset, remaining := 0, decoded; ; {
			logical, rest, more := strings.Cut(remaining, "\n")
			if pos, found := e.findContentAccess([]byte(logical)); pos >= 0 {
				idx, spelling = offset+pos, found
				break
			}
			if !more {
				break
			}
			offset += len(logical) + 1
			remaining = rest
		}
		if idx < 0 {
			continue
		}
		if neg := reNegatedGuidance.FindStringIndex(decoded); neg != nil && neg[0] < idx {
			continue
		}
		r, d := 1, 0
		for d < idx {
			_, size := utf8.DecodeRuneInString(decoded[d:])
			if raw[r] == '\\' {
				if raw[r+1] == 'u' {
					r += 6
					if size == 4 { // A surrogate pair encodes a non-BMP rune.
						r += 6
					}
				} else {
					r += 2
				}
			} else {
				_, rawSize := utf8.DecodeRune(raw[r:])
				r += rawSize
			}
			d += size
		}
		return start + r, spelling
	}
	return -1, nil
}

// Exact file tokens only: .npmrc.example and auth.json.schema are not these
// credential stores. Examine every occurrence so an earlier metadata mention
// cannot hide a later read. Reuse homePrefixes without adding new spellings.
func (e credentialPathSpelling) findContentAccess(line []byte) (int, []byte) {
	if idx, _ := e.find(line); idx < 0 {
		return -1, nil
	}
	line = bytes.TrimSuffix(line, []byte("\r"))
	best, bestSpelling := -1, []byte(nil)
	// Partition substitution nesting once per shell body. Selected program
	// execute bodies are queued separately with original source offsets.
	regions := credentialCommandRegions(line, false)
	for i := 0; i < len(regions); i++ {
		region := regions[i]
		masked := bytes.Clone(region.text)
		var sources, rawSources [][2]int
		var executions []credentialCommandBody
		if !region.language {
			masked, sources, rawSources, executions = maskCredentialCommandData(region.text)
		}
		for _, body := range executions {
			for _, child := range credentialCommandRegions(region.text[body.span[0]:body.span[1]], body.language) {
				for j, offset := range child.offsets {
					child.offsets[j] = region.offsets[body.span[0]+offset]
				}
				regions = append(regions, child)
			}
		}
		// Language literals cannot supply shell children, fallback commands,
		// or nested apparent calls. Only selected filename arguments are reads.
		for _, loc := range region.sources {
			if masked[loc[0]] != ' ' {
				sources = append(sources, loc)
			}
		}
		for _, loc := range region.literals {
			for j := loc[0]; j < loc[1]; j++ {
				masked[j] = ' '
			}
		}
		for _, loc := range reCredentialQuotedLiteral.FindAllIndex(region.text, -1) {
			literal := region.text[loc[0]+1 : loc[1]-1]
			for _, spelling := range e.spellings {
				if !bytes.HasPrefix(literal, spelling) {
					continue
				}
				longer := len(literal) != len(spelling)
				if loc[1] < len(region.text) {
					tail := region.text[loc[1]:]
					sentenceEnd := tail[0] == '.' && (len(tail) == 1 || tail[1] == ' ' || tail[1] == '\t')
					longer = longer || (!bytes.ContainsAny(tail[:1], " \t\r\n),;|&<>]}!?") && !sentenceEnd)
				}
				if longer {
					for i := loc[0]; i < loc[1]; i++ {
						masked[i] = ' '
					}
				}
			}
		}
		for i, source := range sources {
			start, end := source[0], source[1]
			if end-start >= 2 && (region.text[start] == '\'' || region.text[start] == '"') && region.text[end-1] == region.text[start] {
				sources[i] = [2]int{start + 1, end - 1}
			}
		}
		for _, source := range append(sources, rawSources...) {
			start, end := source[0], source[1]
			for _, spelling := range e.spellings {
				if bytes.Equal(region.text[start:end], spelling) && (best < 0 || region.offsets[start] < best) {
					best, bestSpelling = region.offsets[start], spelling
				}
			}
		}
		for _, pattern := range e.contentPatterns {
			if loc := pattern.FindSubmatchIndex(masked); loc != nil && (best < 0 || region.offsets[loc[2]] < best) {
				best = region.offsets[loc[2]]
				bestSpelling = region.text[loc[2]:loc[3]]
			}
		}
	}
	return best, bestSpelling
}

// homePrefixes are the spellings of the user's home directory that a shell or
// an agent expands to the same place. credentialPaths entries beginning with
// `~/` are matched in every one of them; the `~/` spelling stays first so the
// historical match order — and therefore the historical finding description
// on a line that already fired — is unchanged.
//
// This list is evidence-gated, not a catalogue of everything a shell can
// expand. The Windows spellings `$env:USERPROFILE\` and `%USERPROFILE%\` were
// evaluated and deliberately left out: the lines they matched were not
// credential access. Adding a spelling on inference turns this back into a
// deny-list of dangerous forms, which is exactly what the entries here are
// not. Do not add one without the maintainer's sign-off.
var homePrefixes = [][]byte{
	[]byte("~/"),
	[]byte("$HOME/"),
	[]byte("${HOME}/"),
}

// credentialPathSpelling is one credentialPaths entry together with every
// spelling of it that Match() looks for. The canonical entry is what the
// exemptions key on, so widening the spellings cannot silently detach an
// exemption from the path it guards.
type credentialPathSpelling struct {
	canonical       []byte
	spellings       [][]byte
	contentPatterns []*regexp.Regexp
}

// find returns the offset of the LEFTMOST spelling present on the line
// (across every spelling of this entry, not the first one that happens to
// occur), and the spelling found at that offset. idx < 0 when the line names
// none of them. Leftmost, not first-in-homePrefixes-order, because the
// offset feeds reNegatedGuidance's position test in Match() below: "where on
// the line is this path" and "which spelling did we happen to check first"
// are different questions, and returning the wrong one lets a same-entry
// occurrence spelled later in homePrefixes order but earlier on the line
// mask a real, unnegated read of the same path in another spelling.
func (e credentialPathSpelling) find(line []byte) (int, []byte) {
	best, bestSpelling := -1, []byte(nil)
	for _, s := range e.spellings {
		if i := bytes.Index(line, s); i >= 0 && (best < 0 || i < best) {
			best, bestSpelling = i, s
		}
	}
	return best, bestSpelling
}

// credentialPathSpellings is credentialPaths expanded across homePrefixes,
// built once rather than per line: a `~/`-rooted entry contributes one
// spelling per prefix, everything else exactly itself.
var credentialPathSpellings = buildCredentialPathSpellings()

func buildCredentialPathSpellings() []credentialPathSpelling {
	tilde := []byte("~/")
	out := make([]credentialPathSpelling, 0, len(credentialPaths))
	for _, p := range credentialPaths {
		e := credentialPathSpelling{canonical: p}
		if suffix, ok := bytes.CutPrefix(p, tilde); ok {
			for _, prefix := range homePrefixes {
				s := make([]byte, 0, len(prefix)+len(suffix))
				s = append(append(s, prefix...), suffix...)
				e.spellings = append(e.spellings, s)
			}
		} else {
			e.spellings = [][]byte{p}
		}
		if string(p) == "~/.npmrc" || string(p) == "~/.codex/auth.json" {
			var alternatives []string
			for _, spelling := range e.spellings {
				alternatives = append(alternatives, regexp.QuoteMeta(string(spelling)))
			}
			path := "(" + strings.Join(alternatives, "|") + ")"
			e.contentPatterns = []*regexp.Regexp{
				regexp.MustCompile(credentialContentPrefix + path + credentialContentBoundary),
			}
		}
		out = append(out, e)
	}
	return out
}

// reCredentialsModulePath matches a Python import statement naming a module
// path that ends in "credentials" (e.g. `from google.oauth2.credentials
// import Credentials`). The bare ".credentials" entry in credentialPaths is
// a byte-substring match with no word boundary, so it fires inside any
// dotted identifier chain ending in "credentials" — importing a symbol from
// a module is not access to a credentials file; ".credentials" here is a
// package name segment. This exact import line is a recurring shape in honest
// skills, and was not seen on the hostile side, which is what earns it an
// exemption.
//
// Anchored at BOTH ends (only leading/trailing whitespace tolerated), not
// just at line start: review round found the line-start-only anchor let
// anything appended after a real import clause ride along unexamined —
// `from a.credentials import y; import os; os.system('cat ~/.credentials')`
// matched, because Match() only asks whether the pattern occurs somewhere
// in the line. The import-list character class deliberately excludes `.`,
// `;`, quotes and parens-as-call-syntax (only bare identifiers, `*`, `,`,
// whitespace and grouping parens are allowed), so a real function call or
// a second statement appended after the import breaks the match instead of
// riding along. No carve-out for a trailing comment either: in an agent
// manifest the documentation IS the program (the same principle the curated
// attack tripwire enforces elsewhere), so "just a comment" is not a reason to
// trust what follows.
var reCredentialsModulePath = regexp.MustCompile(`(?i)^\s*(from\s+[\w.]+\.credentials\s+import\s+[\w*,\s()]+|import\s+[\w.]+\.credentials(?:\s+as\s+\w+)?)\s*$`)

// reCredentialsFieldDoc matches a Markdown bullet documenting a dotted field
// name ending in "credentials" (e.g. `- broker.credentials.apiKey: API
// key/consumer key`) — a reference-doc entry describing a field, not an
// access to it. As with reDocumentaryContext, shape alone is NOT sufficient
// evidence that a line is documentation: callers MUST also consult
// invokesCommandOnCredentialLine and skip this damping when it matches. That
// pairing is required, not optional — a line matching this shape that also
// runs a command is not documentation.
var reCredentialsFieldDoc = regexp.MustCompile(`^\s*-\s+[\w.]*\.credentials[\w.]*\s*:\s`)

// Deliberately narrow: a bare identifier-chain reference like
// `self.credentials[key]` or `config.credentials.apiKey` does NOT match
// either regex above and still fires. The same "x.credentials" shape appears
// in hostile samples doing real credential harvesting, so a blanket exemption
// for any dotted chain would suppress those too. Only the two unambiguous shapes
// above (import statement, doc bullet) are exempted; adding a third needs the
// maintainer's sign-off.

// reSSHPathToken extracts one whole .ssh/-rooted path token from a line
// (same trailing-terminator exclusion set as reFullPath's path-token class:
// stops at whitespace, quotes, or a shell/Markdown metacharacter that isn't
// part of a filename). Three spellings of the home directory are recognised:
// `~/`, `$HOME/` and `${HOME}/`.
var reSSHPathToken = regexp.MustCompile(`(?:~|\$\{?HOME\}?)/\.ssh/[^\s"')\]>,;|&#${}` + "`" + `]*`)

// allSSHPathsArePublic reports whether EVERY ~/.ssh/-rooted path token on
// the line ends in `.pub`. A public key is meant to be shared and carries
// no secret, unlike the private-key files (id_rsa, id_ed25519) the
// ~/.ssh/ entry otherwise exists to catch — but checking the line as a whole
// for "a .pub reference somewhere" let a second, non-public path on the same
// line ride along unexamined. Requiring EVERY occurrence to be a .pub file is
// what closes that. This must stay a universal test, never an existential
// one.
//
// "Every occurrence" can only mean every occurrence reSSHPathToken
// recognises. That regex was anchored to a literal `~/`, so a second read
// spelled `$HOME/.ssh/id_rsa` or `${HOME}/.ssh/id_rsa` was not a token and
// the line still read as all-public. Two independent closures apply, because
// the hole is reachable two ways:
//
//   - The caller vetoes this exemption with invokesCommandOnCredentialLine,
//     exactly as it already does for reCredentialsFieldDoc: a line that runs
//     a command is not a line documenting a public key, whatever paths it
//     names.
//   - reSSHPathToken itself now recognises the variable spellings, which
//     covers the lines that name a private key with no command on them —
//     an instruction to an agent is a program in an agent manifest.
//
// Keep both. Whether credentialPaths can DETECT a spelling on its own is a
// separate question from whether reSSHPathToken RECOGNISES it here: the token
// only has to be recognised for the line to stop reading as all-public.
//
// The shape this exemption was built for (`# Add
// ~/.ssh/id_ed25519.pub to GitHub Settings -> SSH Keys`, pinned by
// TestSD004_SSHPublicKeyNotFlagged) names one public key with no command on
// it and stays exempt.
func allSSHPathsArePublic(line []byte) bool {
	tokens := reSSHPathToken.FindAll(line, -1)
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		if !bytes.HasSuffix(tok, []byte(".pub")) {
			return false
		}
	}
	return true
}

type credentialAccessRule struct {
	baseRule
}

func (r *credentialAccessRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !InScope(ctx) {
		return nil
	}
	var findings []model.Finding
	isJSON := ctx.Ext == ".json" && json.Valid(content)
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reDocumentaryContext.Match(line) && !invokesCommandOnCredentialLine(line) {
			continue
		}
		for _, entry := range credentialPathSpellings {
			idx, spelling := entry.find(line)
			canonical := string(entry.canonical)
			if len(entry.contentPatterns) > 0 {
				if isJSON {
					idx, spelling = entry.findJSONContentAccess(line)
				} else if idx >= 0 {
					idx, spelling = entry.findContentAccess(line)
				}
			}
			if idx < 0 {
				continue
			}
			if canonical == ".credentials" && (reCredentialsModulePath.Match(line) ||
				(reCredentialsFieldDoc.Match(line) && !invokesCommandOnCredentialLine(line))) {
				continue
			}
			if canonical == "~/.ssh/" && allSSHPathsArePublic(line) &&
				!invokesCommandOnCredentialLine(line) {
				continue
			}
			if loc := reNegatedGuidance.FindIndex(line); loc != nil && loc[0] < idx {
				continue
			}
			desc := fmt.Sprintf("access to credential path %s", string(spelling))
			findings = append(findings, r.newFinding(ctx, lineNum,
				desc,
				"Remove credential path access or document why it's needed"))
			break
		}
	}
	return findings
}

type pathTraversalRule struct {
	baseRule
}

func (r *pathTraversalRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !InScope(ctx) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1

		hasURL := reURLScheme.Match(line)

		if rePathTraversal.Match(line) && !hasURL && !relativeRefStaysInSkill(line, ctx) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"path traversal pattern detected — access outside skill directory",
				"Use relative paths within the skill directory; avoid ../ references"))
		}
		if reAbsolutePath.Match(line) {
			desc := "suspicious absolute path reference outside skill directory"
			if match := reFullPath.FindString(string(line)); match != "" {
				desc = fmt.Sprintf("absolute path reference: %s", match)
			}
			findings = append(findings, r.newFinding(ctx, lineNum,
				desc,
				"Avoid absolute paths to system directories; use relative paths within the skill"))
		}
		if reWindowsPath.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"suspicious Windows absolute path reference",
				"Avoid absolute paths to system directories; use relative paths within the skill"))
		}
	}
	return findings
}

// RegisterAccessControlRules registers all access control detection rules.
func RegisterAccessControlRules(registry *RuleRegistry) {
	registry.Register(&pathTraversalRule{
		baseRule: baseRule{
			id:       "SD-003",
			name:     "Path Traversal",
			severity: model.SeverityHigh,
			category: "Broken Access Control",
			types:    ContentScanTypes,
			axis:     axes.PermissionHygiene,
		},
	})

	registry.Register(&credentialAccessRule{
		baseRule: baseRule{
			id:       "SD-004",
			name:     "Credential Access",
			severity: model.SeverityCritical,
			category: "Broken Access Control",
			types:    ContentScanTypes,
			axis:     axes.PermissionHygiene,
		},
	})
}
