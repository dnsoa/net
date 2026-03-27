package core

import "strconv"

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// ASCIEqualFold reports whether two ASCII byte slices are equal, ignoring case.
func ASCIEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

// asciiEqualFold is the internal lowercase version used within core package.
func asciiEqualFold(a, b []byte) bool {
	return ASCIEqualFold(a, b)
}

// ContainsTokenCI reports whether haystack contains needle as a token,
// comparing case-insensitively. Tokens are delimited by commas and optional whitespace.
func ContainsTokenCI(haystack, needle []byte) bool {
	start := 0
	for start < len(haystack) {
		for start < len(haystack) && (haystack[start] == ' ' || haystack[start] == ',') {
			start++
		}
		end := start
		for end < len(haystack) && haystack[end] != ',' {
			end++
		}
		token := haystack[start:end]
		for len(token) > 0 && token[0] == ' ' {
			token = token[1:]
		}
		for len(token) > 0 && token[len(token)-1] == ' ' {
			token = token[:len(token)-1]
		}
		if ASCIEqualFold(token, needle) {
			return true
		}
		start = end + 1
	}
	return false
}

func AppendInt(dst []byte, v int) []byte {
	return strconv.AppendInt(dst, int64(v), 10)
}
