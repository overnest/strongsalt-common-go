package blocks

import (
	"fmt"

	"github.com/go-errors/errors"
	"github.com/overnest/strongsalt-common-go/tools"
)

// BlockPaddingError represents an error while doing block padding
type BlockPaddingError struct {
	FixedSize uint32
	BlockSize uint32
	Err       *errors.Error
}

// NewBlockPaddingError creates a block padding error
func NewBlockPaddingError(msg string, fixedSize, blockSize uint32) tools.ErrorStack {
	return &BlockPaddingError{fixedSize, blockSize, errors.Wrap(
		fmt.Sprintf("%v : FixedSize=%v BlockSize=%v", msg, fixedSize, blockSize), 1)}
}

// IsBlockPaddingError tests error to see if it's a block padding error
func IsBlockPaddingError(err error) (*BlockPaddingError, bool) {
	if e, ok := err.(*BlockPaddingError); ok {
		return e, true
	}
	return nil, false
}

// Stacktrace shows the stack trace
func (e *BlockPaddingError) Stacktrace() string {
	return e.Err.ErrorStack()
}

// Error shows the error message
func (e *BlockPaddingError) Error() string {
	return e.Err.Error()
}
