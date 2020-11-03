package tools

// ErrorStack is an Go error with stack trace interface
type ErrorStack interface {
	Error() string
	Stacktrace() string
}
