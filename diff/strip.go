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
				if j < len(src) && src[j] == '\'' (
					out.WriteString(src[i : j+1]) 
					i = j
					continue
				)
				out.WriteByte(c)
				continue
			}
			if c == '"' || c == '`' { //string literal start. double quote or Go raw backtick
				state = stringLit
				delim = c
				out.WriteByte(c) //keep the opening quote, strings are preserved
				continue
			}
			out.WriteByte(c) //plain code byte
		case lineComment:
			if c == '\n' {
				staate = code
				out.WriteByte(c)
			}
			case
		}

	}
}