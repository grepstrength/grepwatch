package diff

import "strings"

const (
	langOther = iota //JSON, TOML, YAML, shell, MD... leave untouched
	langC ////, /* */ comment syntax, Go, Rust, JS/TS, Java, Kotline, C#
	langPython
)


//maps a filename to on of the language families above by its extenion
func fileLang(name string) int {
	lower := strings.ToLower(name)
	
	//for the Cish families all share // line comments and /* */ block comments 
	for _, ext := range []string{
		".go", ".rs", ".js", ".ts", ".jsx", ".tsx",
		".mjs", ".cjs", ".java", ".kt", ".scala", ".cs",
	} {
		if strings.HasSuffix(lower, ext) {
			return langC
		}
	}

	//the python family
	for _, ext := range []string{".py", ".pyi"} {
		if strings.HasSuffix(lower, ext) {
			return langPython
		}
	}
	return langOther //unknown extension so caller will leave the content as-is
}

//stripComments is the entry point fro extractor calls. it picks the right state machine for the file's language and returns the source with he commen and docstring regions removed
func stripComments(name, src string) string {
	switch fileLang(name) {
	case langC:
		return stripCStyle(src)
	case langPython:
		return stripPython(src)
	default:
		return src
	}
}

//this removes // line comments and  block comments from c , while preseving string literas verbatim
func stripCStyle(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	const (
		code = iota
		lineComment
		blockComment
		stringLit
	)
	state := code
	var delim byte
	for i := 0; i < len(src); i++ {
		c := src[i]

		switch state {
		case code:
			if c== '/' && i+1 < len(src) && src[i+1] == '/' { //if its a line comment start, needs i+1 in range before peeking at src
				state = lineComment
				i++
				continue
			}
			//block comment
			if c == '/' && i+1 < len(src) && src[i+1] == '*' {
				state = blockComment
				i++ 
				continue
			}
			if c == '\'' {
				j := i + 1
				if j < len(src) && src[j] == '\\' {
					j += 2 //escaped character like '\n' or '\'' covers backslash plus one byte
				} else {
					j++ //plain single char
				}
				if j < len(src) && src[j] == '\'' {
					out.WriteString(src[i : j+1])
					i = j
					continue
			}
				out.WriteByte(c)
				continue
			}
			if c == '"' || c == '`' { //string literal start. double quote or Go raw backtick
				state = stringLit
				delim = c //reember which quote must close it
				out.WriteByte(c) //keep the opening quote, strings are preserved
				continue
			}
			out.WriteByte(c) //plain code byte
		case lineComment:
			if c == '\n' {
				state = code
				out.WriteByte(c)
			}
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = code
				i++  //consume the /
			}
		case stringLit:
			out.WriteByte(c) //everything inside a string is kept
			if delim == '`' { //Go raw string: no escapes, only a backtick closes it
				if c == '`' {
					state = code
				}
				continue
			}
			if c == '\\' && i+1 < len(src) { //a backslash escapes the next byte in a "..." string
				out.WriteByte(src[i+1])
				i++
				continue
			}
			if c == delim {
				state = code
			}
		}
	}
	return out.String()
}

//very similar to stripCStyle, removing # line comments and triple quoted docstrings from Python source
func stripPython(src string) string {
	var out strings.Builder
	out.Grow(len(src))

	const (
		code = iota
		lineComment
		stringLit
		docstring
	)
	state := code
	var delim byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case code:
			if c == '#' {
				state = lineComment
				continue
			}
			//triple quote docstring MUST be checked before the single-quote case
			if (c == '"' || c == '\'') && i+2 < len(src) && src[i+1] == c && src[i+2] == c {
				state = docstring
				delim = c
				i += 2 //consumes the other two quote chars
				continue //docstring body is dropped, so write nothing
			}
			if c == '"' || c == '\'' {
				state = stringLit
				delim = c
				out.WriteByte(c)
				continue
			}
			out.WriteByte(c)

		case lineComment:
			if c == '\n' {
				state = code
				out.WriteByte(c)
			}

		case stringLit:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) { 
				out.WriteByte(src[i+1])
				i++
				continue
			}
			if c == delim {
				state = code
			}

		case docstring:
			if c == delim && i+2 < len(src) && src[i+1] == delim && src[i+2] == delim {
				state = code
				i += 2
			}
		}
	}
	return out.String()
}