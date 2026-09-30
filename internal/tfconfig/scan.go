package tfconfig

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
	// Attributes maps the name of each argument or nested block written directly
	// inside this one to its line. Nothing deeper is recorded: an attribute of
	// an attribute is not an attribute of the resource.
	Attributes map[string]int
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

// scan returns every resource and data declaration in one configuration file.
//
// It returns nil for a file it cannot lex to the end: an unterminated string,
// heredoc or comment, unbalanced braces, or nesting past the bound. This is the
// safety property the milestone rests on. A scanner that reported the positions
// it saw before losing track would be reporting exactly the plausible-but-wrong
// lines that send a reader to the wrong code with the tool's authority behind
// it, and the absence of a location is an answer.
func scan(source []byte) []declaration {
	tokens, ok := lex(source)
	if !ok {
		return nil
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
		case c == ' ' || c == '\t' || c == '\r':
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
	if depth > maxBraceDepth {
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
		case '\n':
			if interpolation == 0 {
				return 0, 0, "", false
			}
			line++
		case '$', '%':
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
	for j < len(source) && identPart(source[j]) {
		j++
	}
	tag := string(source[tagStart:j])
	if tag == "" {
		// Not a heredoc at all. Refusing the file is the honest answer: this
		// build does not know what it is reading.
		return 0, 0, false
	}

	// The rest of the opening line belongs to the heredoc marker.
	j = endOfLine(source, j)
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
func declarationsIn(tokens []token) []declaration {
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
				current = headerDeclaration(tokens, header)
				header = nil
			}
			depth++
			if depth > maxBraceDepth {
				return nil
			}
		case tokenClose:
			depth--
			if depth < 0 {
				return nil
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
		return nil
	}
	return out
}

// headerDeclaration reads a block header, or reports that the window is not one.
func headerDeclaration(tokens []token, header []int) *declaration {
	if len(header) != 3 || !startsStatement(tokens, header[0]) {
		return nil
	}
	keyword, first, second := tokens[header[0]], tokens[header[1]], tokens[header[2]]
	if keyword.kind != tokenIdent || first.kind != tokenString || second.kind != tokenString {
		return nil
	}
	if keyword.text != "resource" && keyword.text != "data" {
		return nil
	}
	return &declaration{
		Kind:       keyword.text,
		Type:       first.text,
		Name:       second.text,
		Line:       keyword.line,
		Attributes: map[string]int{},
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
	if next := tokens[i+1].kind; next != tokenEquals && next != tokenOpen {
		return
	}
	if _, seen := current.Attributes[tk.text]; !seen {
		current.Attributes[tk.text] = tk.line
	}
}

// startsStatement reports whether the token at i begins something rather than
// continuing it.
//
// HCL separates arguments by newline, so an identifier that opens a line, or
// follows a brace, is a name; one that follows another token on the same line is
// part of an expression -- the "assets" in aws_s3_bucket.assets.id is not an
// argument called assets.
func startsStatement(tokens []token, i int) bool {
	if i == 0 {
		return true
	}
	previous := tokens[i-1]
	return previous.kind == tokenOpen || previous.kind == tokenClose || previous.line < tokens[i].line
}
