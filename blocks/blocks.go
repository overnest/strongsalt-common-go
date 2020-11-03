package blocks

const (
	_ = iota // Skip 0
	// BlockListV1 is block list version 1
	BlockListV1 = uint32(iota)

	// BlockListCurV is the current version of block list
	BlockListCurV = BlockListV1
)

// BlockList is the interface for the list of blocks
type BlockList interface {
	GetVersion() uint32
}

// Block is the interface for each block in the block list.
// Do not modify or remove functions from here. Otherwise
// the code will not be able to parse older block versions
type Block interface {
	GetID() uint32
	GetSize() uint32
	GetData() []byte
}

// NewBlockListWriter creates a block list for writing only
//
func NewBlockListWriter(store interface{}, paddedSize uint32) (BlockList, error) {
	return NewBlockListWriterV1(store, paddedSize)
}

// NewBlockListReader creates a block list for reading only
//
func NewBlockListReader(store interface{}, initOffset, endOffset uint64) (BlockList, error) {
	return NewBlockListReaderV1(store, initOffset, endOffset)
}
