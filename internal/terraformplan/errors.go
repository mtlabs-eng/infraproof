package terraformplan

import (
	"errors"
	"fmt"
)

// ErrUnsupportedFormatVersion reports plan JSON written in a format version
// this build does not implement. Callers match it with errors.Is to separate an
// unsupported input from a malformed one.
var ErrUnsupportedFormatVersion = errors.New("unsupported plan format version")

// ParseError reports one problem with the input. It carries a field path and an
// explanation and has no field capable of holding a value, so reporting a
// problem on a sensitive field cannot disclose that field.
type ParseError struct {
	// Path locates the problem, such as "resource_changes[3].change.actions".
	Path string
	// Message explains it without quoting any plan value.
	Message string

	cause error
}

// Error renders the problem as "terraformplan: path: message".
func (e *ParseError) Error() string {
	if e.Path == "" {
		return "terraformplan: " + e.Message
	}
	return "terraformplan: " + e.Path + ": " + e.Message
}

// Unwrap exposes the sentinel a caller may want to match.
func (e *ParseError) Unwrap() error { return e.cause }

// invalid builds a ParseError for the given field path.
func invalid(path, format string, args ...any) error {
	return &ParseError{Path: path, Message: fmt.Sprintf(format, args...)}
}

// unsupported builds a ParseError that matches ErrUnsupportedFormatVersion.
func unsupported(path, format string, args ...any) error {
	return &ParseError{Path: path, Message: fmt.Sprintf(format, args...), cause: ErrUnsupportedFormatVersion}
}
