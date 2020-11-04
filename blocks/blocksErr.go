package blocks

import (
	"fmt"

	"github.com/go-errors/errors"
	"github.com/overnest/strongsalt-common-go/tools"
)

// BlockPaddingError represents an error while doing block padding
type BlockPaddingError struct {
	PaddedBlockSize uint32
	BlockSize       uint32
	MaxDataSize     uint32
	Err             *errors.Error
}

// NewBlockPaddingError creates a block padding error
func NewBlockPaddingError(msg string, paddedSize, blockSize, maxDataSize uint32) tools.ErrorStack {
	return &BlockPaddingError{
		paddedSize,
		blockSize,
		maxDataSize,
		errors.Wrap(fmt.Sprintf("%v : PaddedSize=%v BlockSize=%v MaxDataSize=%v",
			msg, paddedSize, blockSize, maxDataSize), 1)}
}

// IsBlockPaddingError tests error to see if it's a block padding error
func IsBlockPaddingError(err error) (*BlockPaddingError, bool) {
	if e, ok := err.(*errors.Error); ok {
		if e, ok := e.Err.(*BlockPaddingError); ok {
			return e, true
		}
	}

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
