package blocks

import "github.com/overnest/strongsalt-common-go/tools"

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

// BlockDataComparator is a comparator function definition.
// Returns:
//   < 0      , if value < block
//   1        , if value is in block
//   0        , if value not in block
//   > 1      , if value > block
type BlockDataComparator func(value interface{}, blockData interface{}) (int, error)

// initialize empty block data struct
type InitEmptyBlockData func() interface{}

//
// A padded block list will make sure that every block is the same size by
//    1. Padding smaller blocks into a bigger, fixed size
//    2. Not allow blocks large than the padded size to be written
//
// This will allow the user to perform a binary search on the block list if
// the block data is sorted.
//

// NewBlockListWriter creates a block list for writing only
//
func NewBlockListWriter(store interface{}, paddedBlockSize uint32, initOffset uint64) (BlockList, error) {
	return NewBlockListWriterV1(store, paddedBlockSize, initOffset)
}

// NewBlockListReader creates a block list for reading only
//
func NewBlockListReader(store interface{}, initOffset, endOffset uint64, initBlockData InitEmptyBlockData) (BlockList, error) {
	return NewBlockListReaderV1(store, initOffset, endOffset, initBlockData)
}

func GetPredictedJSONSize(data interface{}) (int, error) {
	dataBytes, err := tools.Marshal(data)
	if err != nil {
		return 0, err
	}
	return len(dataBytes), nil
}
