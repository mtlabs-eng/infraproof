package tfconfig

import "bytes"

// declaration is one resource or data block found in a configuration file, with
// the line it is written on and the lines of the attributes written directly
// inside it.
//
// It carries no text from the file. A location is a path and a line: a .tf file
// holds secrets more often than a plan does, and the only way to be sure none
// reaches output is for none to be kept.
type declaration struct {
	// Kind is "resource" or "data", matching the block keyword.
	Kind string
	// Type and Name are the block's two labels.
	Type, Name string
	// Line is the 1-based line the block keyword is on.
	Line int
	// Attributes are the arguments and unlabelled nested blocks written directly
	// inside this one, with the line each is on, in the order they appear.
	// Nothing deeper is recorded: an attribute of an attribute is not an
	// attribute of the resource.
	//
	// A slice rather than a map because a declaration has a handful of them and
	// a directory can have tens of thousands of declarations: a map per
	// declaration costs more in headers than the whole configuration it came
	// from. Measured at this build's own reading bound, the maps were most of a
	// 24-fold amplification of the bytes read.
	Attributes []attribute
}

// attribute is one argument or nested block, and the line it is written on.
type attribute struct {
	name string
	line int
}

// lineOf returns the line an argument is written on, and whether it is written
// in this block at all.
func (d declaration) lineOf(name string) (int, bool) {
	for _, a := range d.Attributes {
		if a.name == name {
			return a.line, true
		}
	}
	return 0, false
}

// maxBraceDepth bounds how deeply a file may nest before the scan refuses it.
//
// Real configuration nests a handful of levels. The bound is not about cost --
// the scan is linear either way -- but about staying in a range where losing
// track is impossible rather than merely unlikely.
const maxBraceDepth = 64

// maxTokens bounds how many tokens one file may produce. A file past it is
// refused rather than lexed, for the reason the guard refuses a large directory.
const maxTokens = 1 << 18

// scan returns every resource and data declaration in one configuration file,
// and whether the file could be read at all.
//
// It reports false for a file it cannot lex to the end: an unterminated string,
// heredoc or comment, unbalanced braces, nesting past a bound, or a construct
// this build does not know how to read. This is the safety property the milestone
// rests on. A scanner that reported the positions it saw before losing track
// would be reporting exactly the plausible-but-wrong lines that send a reader to
// the wrong code with the tool's authority behind it, and the absence of a
// location is an answer.
//
// The two answers are separate because they are different facts. A file with no
// declarations in it -- one that only calls modules, say -- was read completely
// and has nothing to offer; a file that was refused may have had everything in
// it. Both yield no location, so nothing downstream branches on the difference,
// and returning one value for both left this package unable to say whether it had
// refused the whole repository. A test asks it now.
func scan(source []byte) ([]declaration, bool) {
	tokens, ok := lex(source)
	if !ok {
		return nil, false
	}
	return declarationsIn(tokens)
}

// tokenKind is the part of the grammar a token belongs to. Only what a block
// header and an attribute name are made of is distinguished; everything else is
// one kind, because nothing here evaluates an expression.
type tokenKind uint8

const (
	tokenOther tokenKind = iota
	tokenIdent
	tokenString
	tokenOpen
	tokenClose
	tokenEquals
)

type token struct {
	kind tokenKind
	// text is the identifier, or a quoted string's contents exactly as written.
	// Escapes are not interpreted: a label containing one is not a resource type
	// any plan states, so it will match nothing, which is the safe answer.
	text string
	line int
}

// lex turns a configuration file into tokens, or reports that it could not.
//
// Comments and heredoc bodies produce no tokens at all. That is the difference
// between this and a search: a heredoc holding what reads like a resource block
// is a string, and a scanner that does not know it shifts every line after it.
func lex(source []byte) ([]token, bool) {
	var tokens []token
	line := 1
	i := 0
	// A byte order mark is not content. Terraform reads a file that starts with
	// one; leaving it in made its three bytes the token before the first keyword,
	// which is how startsStatement came to decide that the first declaration in
	// the file does not begin a statement, and the file's first declaration was
	// silently invisible.
	if bytes.HasPrefix(source, []byte{0xef, 0xbb, 0xbf}) {
		i = 3
	}

	emit := func(kind tokenKind, text string, at int) bool {
		if len(tokens) >= maxTokens {
			return false
		}
		tokens = append(tokens, token{kind: kind, text: text, line: at})
		return true
	}

	for i < len(source) {
		c := source[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t':
			i++
		case c == '\r':
			// Only as part of a line ending. Terraform refuses a carriage return
			// anywhere else -- "this character is not used within the language" --
			// and treating one as whitespace let a name and its "=" sit on one
			// lexer line while the file has them on two, which is a position
			// claimed in a file nothing could have planned.
			if i+1 >= len(source) || source[i+1] != '\n' {
				return nil, false
			}
			i++
		case c == '#':
			i = endOfLine(source, i)
		case c == '/' && i+1 < len(source) && source[i+1] == '/':
			i = endOfLine(source, i)
		case c == '/' && i+1 < len(source) && source[i+1] == '*':
			end, endLine, ok := blockComment(source, i, line)
			if !ok {
				return nil, false
			}
			i, line = end, endLine
		case c == '"':
			end, endLine, text, ok := quoted(source, i, line, 0)
			if !ok {
				return nil, false
			}
			if !emit(tokenString, text, line) {
				return nil, false
			}
			i, line = end, endLine
		case c == '<' && i+1 < len(source) && source[i+1] == '<':
			end, endLine, ok := heredoc(source, i, line)
			if !ok {
				return nil, false
			}
			// The body was a value, and no token stands for it: nothing in this
			// package reads a value.
			i, line = end, endLine
		case c == '{':
			if !emit(tokenOpen, "", line) {
				return nil, false
			}
			i++
		case c == '}':
			if !emit(tokenClose, "", line) {
				return nil, false
			}
			i++
		case c == '=':
			if i+1 < len(source) && source[i+1] == '=' {
				// An equality operator is not an assignment, and reading it as
				// one would make the left of a comparison look like an argument.
				if !emit(tokenOther, "", line) {
					return nil, false
				}
				i += 2
				break
			}
			if !emit(tokenEquals, "", line) {
				return nil, false
			}
			i++
		case identStart(c):
			end := i + 1
			for end < len(source) && identPart(source[end]) {
				end++
			}
			if !emit(tokenIdent, string(source[i:end]), line) {
				return nil, false
			}
			i = end
		default:
			if !emit(tokenOther, "", line) {
				return nil, false
			}
			i++
		}
	}
	return tokens, true
}

// endOfLine returns the index of the newline ending the line at i, or the end of
// the input. The newline itself is left for the caller to count.
func endOfLine(source []byte, i int) int {
	for i < len(source) && source[i] != '\n' {
		i++
	}
	return i
}

// blockComment skips /* ... */ and counts the lines inside it.
func blockComment(source []byte, i, line int) (int, int, bool) {
	for j := i + 2; j < len(source); j++ {
		if source[j] == '\n' {
			line++
			continue
		}
		if source[j] == '*' && j+1 < len(source) && source[j+1] == '/' {
			return j + 2, line, true
		}
	}
	return 0, 0, false
}

// quoted skips a quoted template and returns its literal contents.
//
// The hard part is that a template is not a string: "${...}" holds an
// expression, which holds strings, which hold templates. Braces and quotes
// inside one say nothing about the structure of the file, so the nesting is
// followed rather than guessed at, and depth is what tells them apart.
//
// A literal newline is allowed only inside an interpolation. Outside one HCL
// does not permit it, and treating an unterminated string as if it continued on
// the next line is how a lexer loses a file's structure without noticing.
func quoted(source []byte, i, line, depth int) (int, int, string, bool) {
	if depth >= maxBraceDepth {
		return 0, 0, "", false
	}

	interpolation := 0
	start := i + 1
	for j := start; j < len(source); j++ {
		switch source[j] {
		case '\\':
			// Whatever follows is literal, including a quote and a backslash.
			j++
			if j >= len(source) {
				return 0, 0, "", false
			}
			if source[j] == '\n' {
				// HCL has no line continuation in a quoted template. Reading one
				// as an escape accepts a string HCL refuses and, worse, consumes
				// a newline without counting it -- so every line after it is
				// reported one too low. The fuzzer found this by comparing a
				// reported line against the text actually on it.
				return 0, 0, "", false
			}
		case '\n':
			if interpolation == 0 {
				return 0, 0, "", false
			}
			line++
		case '$', '%':
			// "$${" and "%%{" are how a template writes a literal "${" or "%{",
			// so the second sigil opens nothing. Reading one as an interpolation
			// left the counter high for the rest of the string, and the file --
			// which Terraform accepts -- was refused whole, so nothing in it had
			// a location and the bundle did not say why.
			if j+1 < len(source) && source[j+1] == source[j] {
				j++
				break
			}
			if j+1 < len(source) && source[j+1] == '{' {
				interpolation++
				j++
			}
		case '{':
			if interpolation > 0 {
				interpolation++
			}
		case '}':
			if interpolation > 0 {
				interpolation--
			}
		case '#':
			// An expression may carry a comment, and a brace or a quote in one
			// says nothing about the template around it. Outside an
			// interpolation "#" is ordinary text.
			if interpolation > 0 {
				j = endOfLine(source, j) - 1
			}
		case '/':
			if interpolation > 0 && j+1 < len(source) && source[j+1] == '/' {
				j = endOfLine(source, j) - 1
				break
			}
			if interpolation > 0 && j+1 < len(source) && source[j+1] == '*' {
				end, endLine, ok := blockComment(source, j, line)
				if !ok {
					return 0, 0, "", false
				}
				j, line = end-1, endLine
			}
		case '"':
			if interpolation == 0 {
				return j + 1, line, string(source[start:j]), true
			}
			// A string inside the expression inside this one.
			end, endLine, _, ok := quoted(source, j, line, depth+1)
			if !ok {
				return 0, 0, "", false
			}
			j, line = end-1, endLine
		}
	}
	return 0, 0, "", false
}

// heredoc skips a heredoc and counts its lines.
//
// The terminator is the first line whose only content is the tag, for both
// <<TAG and <<-TAG: the dash changes how Terraform dedents the body, not how the
// body ends.
func heredoc(source []byte, i, line int) (int, int, bool) {
	j := i + 2
	if j < len(source) && source[j] == '-' {
		j++
	}
	tagStart := j
	// An identifier does not start with a digit or a dash, so a marker that does
	// has no tag at all and the file is refused below. Terraform refuses both
	// forms, and reading "<<9EOT" as a heredoc tagged 9EOT meant this build read
	// a file as configuration that Terraform reads as an error.
	if j < len(source) && identStart(source[j]) {
		j++
		for j < len(source) && identPart(source[j]) {
			j++
		}
	}
	tag := string(source[tagStart:j])
	// An HCL identifier is Unicode and identPart is not, so a tag with a letter
	// outside ASCII stops early and what this build holds is a proper prefix of
	// the real terminator. The heredoc then ends at the first body line equal to
	// that prefix, and everything up to the real terminator is lexed as
	// structure: independent review built a file Terraform validates and plans,
	// where an argument's position came out four lines from where it is written
	// and a declaration was reported that exists only inside a string.
	//
	// Refusing is enough, and refusing is already the answer to a file this
	// build cannot read. Reading the tag as a real Unicode identifier would be
	// more than is needed, and the rest of this lexer is ASCII by the same
	// choice -- there it only loses an attribute, here it moves a line.
	if j < len(source) && source[j] >= 0x80 {
		return 0, 0, false
	}
	if tag == "" {
		// Not a heredoc at all. Refusing the file is the honest answer: this
		// build does not know what it is reading.
		return 0, 0, false
	}

	// Nothing may follow the marker. Terraform refuses it, and swallowing it
	// meant this build read a file as a heredoc that Terraform reads as an error.
	rest := endOfLine(source, j)
	if trimmed(source[j:rest]) != "" {
		return 0, 0, false
	}
	j = rest
	for j < len(source) {
		j++ // the newline ending the previous line
		line++
		end := endOfLine(source, j)
		if trimmed(source[j:end]) == tag {
			return end, line, true
		}
		j = end
	}
	return 0, 0, false
}

// trimmed returns a line without its surrounding horizontal whitespace.
func trimmed(line []byte) string {
	start, end := 0, len(line)
	for start < end && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t' || line[end-1] == '\r') {
		end--
	}
	return string(line[start:end])
}

func identStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func identPart(c byte) bool {
	return identStart(c) || c == '-' || c >= '0' && c <= '9'
}

// declarationsIn reads the declarations out of a token stream.
//
// A declaration is a top-level block, and only a top-level block. Something
// shaped like one nested inside another block is not a declaration a plan can
// contain, so reporting its line would be reporting a position for a resource
// that does not exist.
func declarationsIn(tokens []token) ([]declaration, bool) {
	var out []declaration
	var current *declaration

	// header holds the indices of the last three tokens seen at the top level.
	// A sliding window rather than everything since the last brace: whatever
	// else a file has at the top level, a block header is its last three tokens
	// before the brace, and a window cannot be thrown off by what preceded it.
	var header []int
	depth := 0

	for i, tk := range tokens {
		switch tk.kind {
		case tokenOpen:
			if depth == 0 {
				current = headerDeclaration(tokens, header, tk)
				// Clearing it here changes nothing a test can see, and
				// independent review found that out by mutation: tokens inside a
				// block never reach the window, and the closing brace clears it
				// again, so the only file that could tell is one whose block
				// never closes -- which is refused whole. It stays because the
				// window is about what precedes a brace, and leaving a consumed
				// header in it would be a fact about the file that is no longer
				// true.
				header = nil
			}
			depth++
			if depth > maxBraceDepth {
				return nil, false
			}
		case tokenClose:
			depth--
			if depth < 0 {
				return nil, false
			}
			if depth == 0 {
				if current != nil {
					out = append(out, *current)
					current = nil
				}
				header = nil
			}
		default:
			if depth == 0 {
				header = append(header, i)
				if len(header) > 3 {
					header = header[1:]
				}
				continue
			}
			if depth == 1 && current != nil {
				recordAttribute(current, tokens, i)
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	return out, true
}

// headerDeclaration reads a block header, or reports that the window is not one.
//
// All of it on one line, including the brace. HCL ends a header at a newline, so
// a keyword on one line and its labels on the next is a file Terraform refuses --
// and this build read it as a declaration, reporting the keyword's line. The
// fuzzer found that by disagreeing with an oracle that asks what a line is
// actually used for, which was the oracle being right.
func headerDeclaration(tokens []token, header []int, brace token) *declaration {
	if len(header) != 3 || !startsStatement(tokens, header[0]) {
		return nil
	}
	keyword, first, second := tokens[header[0]], tokens[header[1]], tokens[header[2]]
	if keyword.line != first.line || first.line != second.line || second.line != brace.line {
		return nil
	}
	if keyword.kind != tokenIdent || first.kind != tokenString || second.kind != tokenString {
		return nil
	}
	if keyword.text != "resource" && keyword.text != "data" {
		return nil
	}
	return &declaration{
		Kind: keyword.text,
		Type: first.text,
		Name: second.text,
		Line: keyword.line,
	}
}

// recordAttribute records an argument or nested block written directly inside a
// declaration.
//
// The first of a repeated name is kept. Terraform would refuse the file, but
// this build cannot assume the files it reads are the ones the plan came from,
// and choosing the first is a stated reading rather than whichever the loop
// happened to end on.
func recordAttribute(current *declaration, tokens []token, i int) {
	tk := tokens[i]
	if tk.kind != tokenIdent || !startsStatement(tokens, i) || i+1 >= len(tokens) {
		return
	}
	// On the same line as the name. HCL writes an argument and its "=" together,
	// and a block header and its brace together; without the check the token
	// matched against could be arbitrarily far away -- a heredoc or a run of
	// blank lines later -- and the position claimed would be for something else.
	if next := tokens[i+1]; next.line != tk.line || next.kind != tokenEquals && next.kind != tokenOpen {
		return
	}
	if _, seen := current.lineOf(tk.text); !seen {
		current.Attributes = append(current.Attributes, attribute{name: tk.text, line: tk.line})
	}
}

// startsStatement reports whether the token at i begins something rather than
// continuing it.
//
// HCL separates arguments and blocks by newline, so a name is the first token on
// its line and nothing else is: the "assets" in aws_s3_bucket.assets.id is not an
// argument called assets, and neither is the "x" in "{ x = 1 }" written on the
// same line as the brace that opens it, because Terraform refuses that file.
//
// An earlier version also accepted a name straight after a brace on the same
// line. That is HCL this build would never be given -- Terraform reports
// "Missing newline after block definition" -- and accepting it meant claiming a
// position inside a file nothing could have planned. The fuzzer found it by
// disagreeing with a stricter oracle, which was the oracle being right.
func startsStatement(tokens []token, i int) bool {
	if i == 0 {
		return true
	}
	return tokens[i-1].line < tokens[i].line
}
