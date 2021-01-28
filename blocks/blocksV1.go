package blocks

import (
	"encoding/binary"
	"io"
	"math"
	"math/rand"

	"github.com/go-errors/errors"
)

//
// A padded block list will make sure that every block is the same size by
//    1. Padding smaller blocks into a bigger, fixed size
//    2. Not allow blocks large than the padded size to be written
//
// This will allow the user to perform a binary search on the block list if
// the block data is sorted.
//

// BlockListWriterV1 is the block list writer interface for version 1
type BlockListWriterV1 interface {
	GetVersion() uint32
	IsBlockPadded() bool
	GetPaddedBlockSize() uint32
	GetMaxDataSize() uint32
	GetTotalBlocks() (uint32, error)
	WriteBlock(block Block) error
	WriteBlockData(data []byte) (Block, error)
}

// BlockListReaderV1 is the block list reader interface for version 1
type BlockListReaderV1 interface {
	GetVersion() uint32
	IsBlockPadded() bool
	GetPaddedBlockSize() uint32
	GetTotalBlocks() (uint32, error)
	GetCurBlock() Block
	ReadNextBlock() (Block, error)
	ReadBlockAt(index uint32) (Block, error)
	Reset() error
	SearchLinear(value interface{}, comparator Comparator) (Block, error)
	SearchBinary(value interface{}, comparator Comparator) (Block, error)
}

type blockListV1 struct {
	version         uint32
	paddedBlockSize uint32
	curBlock        Block
	writer          io.Writer
	reader          io.Reader
	readerat        io.ReaderAt
	seeker          io.Seeker
	initOffset      uint64
	curOffset       uint64
	endOffset       uint64
}

type blockV1 struct {
	id   uint32
	size uint32
	data []byte
}

const (
	versionLen         = uint32(4)
	padSizeLen         = uint32(4)
	blockListHeaderLen = versionLen + padSizeLen

	blockNumLen    = uint32(4)
	blockSizeLen   = uint32(4)
	blockHeaderLen = blockNumLen + blockSizeLen
)

// NewBlockListWriterV1 creates a block list version 1 writer
func NewBlockListWriterV1(store interface{}, paddedBlockSize uint32, initOffset uint64) (BlockListWriterV1, error) {
	var ok bool
	b := &blockListV1{BlockListV1, paddedBlockSize, nil, nil, nil, nil, nil, initOffset, 0, 0}

	if b.writer, ok = store.(io.Writer); !ok {
		return nil, errors.New("The storage must implement io.Writer")
	}

	if b.IsBlockPadded() {
		if _, ok = store.(io.ReaderAt); !ok {
			return nil, errors.New(`A padded block list allows random access, 
				which requires the storage to implement io.ReaderAt`)
		}
	}

	version := make([]byte, versionLen)
	binary.BigEndian.PutUint32(version, b.GetVersion())
	padSize := make([]byte, padSizeLen)
	binary.BigEndian.PutUint32(padSize, b.GetPaddedBlockSize())

	n, err := b.writer.Write(version)
	if err != nil {
		return nil, errors.New(err)
	}
	if n != len(version) {
		return nil, errors.New("Can not write version data to storage")
	}

	n, err = b.writer.Write(padSize)
	if err != nil {
		return nil, errors.New(err)
	}
	if n != len(version) {
		return nil, errors.New("Can not write padded block size data to storage")
	}

	b.initOffset += uint64((len(version) + len(padSize)))
	b.curOffset = b.initOffset
	b.endOffset = b.curOffset

	return b, nil
}

// NewBlockListReaderV1 creates a block list version 1 reader
func NewBlockListReaderV1(store interface{}, initOffset, endOffset uint64) (BlockListReaderV1, error) {
	var ok bool
	b := &blockListV1{BlockListV1, 0, nil, nil, nil, nil, nil, initOffset, initOffset, endOffset}

	if b.reader, ok = store.(io.Reader); !ok {
		return nil, errors.New("The storage must implement io.Reader")
	}

	version := make([]byte, versionLen)
	n, err := b.reader.Read(version)
	if err != nil {
		return nil, errors.New(err)
	}
	if n != len(version) {
		return nil, errors.New("Can not read version data from storage")
	}
	b.version = binary.BigEndian.Uint32(version)

	paddedBlockSize := make([]byte, padSizeLen)
	n, err = b.reader.Read(paddedBlockSize)
	if err != nil {
		return nil, errors.New(err)
	}
	if n != len(paddedBlockSize) {
		return nil, errors.New("Can not read padded block size data from storage")
	}

	b.paddedBlockSize = binary.BigEndian.Uint32(paddedBlockSize)
	if b.IsBlockPadded() {
		if b.readerat, ok = store.(io.ReaderAt); !ok {
			return nil, errors.New(`A padded block list allows random access, 
				which requires the storage to implement io.ReaderAt`)
		}

		if endOffset < 1 {
			return nil, errors.New(`A padded block list allows random access, 
				which requires the code to have and endOffset > 0`)
		}

		// We don't necessarily need seek function. But it's nice to have
		if b.seeker, ok = store.(io.Seeker); !ok {
			b.seeker = nil
		}
	}

	b.initOffset += uint64((len(version) + len(paddedBlockSize)))
	b.curOffset = b.initOffset

	return b, nil
}

func (b *blockListV1) GetVersion() uint32 {
	return b.version
}

func (b *blockListV1) IsBlockPadded() bool {
	return (b.paddedBlockSize > 0)
}

func (b *blockListV1) GetPaddedBlockSize() uint32 {
	return b.paddedBlockSize
}

func (b *blockListV1) GetMaxDataSize() uint32 {
	if b.IsBlockPadded() {
		return b.GetPaddedBlockSize() - 8
	}

	return math.MaxUint32
}

func (b *blockListV1) checkListValid() error {
	if b.endOffset < b.initOffset {
		return errors.Errorf("The initial offset(%v) of the block list is "+
			"bigger than the end offset(%v)", b.initOffset, b.endOffset)
	}

	if b.IsBlockPadded() {
		blockBytes := b.endOffset - b.initOffset
		if blockBytes%uint64(b.GetPaddedBlockSize()) > 0 {
			return errors.Errorf("The number of block bytes(%v) does "+
				"not divide evenly by padded block size(%v).", blockBytes,
				b.GetPaddedBlockSize())
		}
	}

	return nil
}

func (b *blockListV1) GetTotalBlocks() (uint32, error) {
	if !b.IsBlockPadded() {
		return 0, errors.New("The block list does not have padded fix sized blocks. " +
			"Can not precalculate total blocks")
	}

	if err := b.checkListValid(); err != nil {
		return 0, err
	}

	blockBytes := b.endOffset - b.initOffset
	return uint32(blockBytes / uint64(b.GetPaddedBlockSize())), nil
}

func (b *blockListV1) GetCurBlock() Block {
	return b.curBlock
}

func (b *blockListV1) ReadNextBlock() (Block, error) {
	if b.reader == nil {
		return nil, errors.New("The underlying storage is not capable " +
			"of performing reads")
	}
	var n int
	var err error
	var blockBytes []byte

	if b.IsBlockPadded() {
		blockBytes = make([]byte, b.GetPaddedBlockSize())
		if n, err = b.reader.Read(blockBytes); err != nil {
			if err == io.EOF {
				return nil, err
			}
			return nil, errors.New(err)
		}
		if n != len(blockBytes) {
			return nil, errors.Errorf("Expecting %v bytes but read %v", len(blockBytes), n)
		}
	} else {
		hdr := make([]byte, blockHeaderLen)
		if n, err = b.reader.Read(hdr); err != nil {
			if err == io.EOF {
				return nil, err
			}
			return nil, errors.New(err)
		}
		if n != len(hdr) {
			return nil, errors.Errorf("Expecting %v bytes but read %v", len(hdr), n)
		}

		blockNum := binary.BigEndian.Uint32(hdr[:blockNumLen])
		_ = blockNum // Not used
		blockSize := binary.BigEndian.Uint32(hdr[blockNumLen:])
		blockData := make([]byte, blockSize)
		if n, err = b.reader.Read(blockData); err != nil {
			if err == io.EOF {
				return nil, err
			}
			return nil, errors.New(err)
		}
		if n != len(blockData) {
			return nil, errors.Errorf("Expecting %v bytes but read %v", len(blockData), n)
		}

		blockBytes = append(hdr, blockData...)
		n = len(blockBytes)
	}

	blockv1, err := DeserializeBlockV1(b.GetPaddedBlockSize(), blockBytes)
	if err != nil {
		return nil, err
	}

	if b.GetCurBlock() != nil {
		if blockv1.GetID() != b.GetCurBlock().GetID()+1 {
			return nil, errors.Errorf("The next block ID(%v) does not immediately follow "+
				"the previous block ID(%v)", blockv1.GetID(), b.GetCurBlock().GetID())
		}
	}

	b.curOffset += uint64(len(blockBytes))
	b.curBlock = blockv1
	return blockv1, nil
}

func (b *blockListV1) ReadBlockAt(index uint32) (Block, error) {
	if !b.IsBlockPadded() {
		return nil, errors.New("The block list does not have padded fixed sized blocks. " +
			"Can not perform random access reads")
	}

	if b.readerat == nil {
		return nil, errors.New("The underlying storage is not capable " +
			"of performing random access reads")
	}

	blockBytes := make([]byte, b.GetPaddedBlockSize())
	offset := b.initOffset + (uint64(b.GetPaddedBlockSize()) * uint64(index))

	n, err := b.readerat.ReadAt(blockBytes, int64(offset))
	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, errors.New(err)
	}
	if n != len(blockBytes) {
		return nil, errors.Errorf("Expecting %v bytes but only read %v", len(blockBytes), n)
	}

	block, err := DeserializeBlockV1(b.GetPaddedBlockSize(), blockBytes)
	if err != nil {
		return nil, err
	}
	if block.GetID() != index {
		return nil, errors.Errorf("Block ID(%v) does not match the retrieval index(%v)",
			block.GetID(), index)
	}

	return block, nil
}

func (b *blockListV1) WriteBlockData(data []byte) (Block, error) {
	block := &blockV1{0, uint32(len(data)), data}

	if b.GetCurBlock() != nil {
		block.id = b.GetCurBlock().GetID() + 1
	}

	err := b.WriteBlock(block)
	return block, err
}

func (b *blockListV1) WriteBlock(block Block) error {
	var blockv1 *blockV1
	var ok bool

	if b.writer == nil {
		return errors.New("This is not a block list writer")
	}

	if blockv1, ok = block.(*blockV1); !ok {
		return errors.New("Version 1 block list can only accept version 1 blocks")
	}

	if b.GetCurBlock() != nil {
		blockv1.id = b.GetCurBlock().GetID() + 1
	}

	serial, err := blockv1.Serialize(b.GetPaddedBlockSize())
	if err != nil {
		return errors.New(err)
	}

	n, err := b.writer.Write(serial)
	if err != nil {
		return errors.New(err)
	}
	if n != len(serial) {
		return errors.New("Can not write complete block to storage")
	}

	b.curOffset += uint64(n)
	b.endOffset = b.curOffset
	b.curBlock = blockv1

	return nil
}

func (b *blockListV1) Reset() error {
	if b.seeker != nil {
		_, err := b.seeker.Seek(int64(b.initOffset), io.SeekStart)
		if err != nil {
			return errors.New(err)
		}
		b.curBlock = nil
		b.curOffset = b.initOffset
		return nil
	}

	return errors.Errorf("Seeker interface not implemented. Can not reset")
}

func (b *blockListV1) SearchLinear(value interface{}, comparator Comparator) (Block, error) {
	if b.reader == nil {
		return nil, errors.New("The underlying storage is not capable " +
			"of performing reads")
	}

	err := b.Reset()
	if err != nil {
		return nil, err
	}

	for true {
		block, err := b.ReadNextBlock()
		if err != nil && err != io.EOF {
			return nil, errors.New(err)
		}

		if block != nil {
			comp, err := comparator(value, block)
			if err != nil {
				return nil, errors.New(err)
			}
			// Found
			if comp == 1 {
				return block, nil
			}
		}

		if err != nil {
			break
		}
	}

	return nil, nil
}

func (b *blockListV1) SearchBinary(value interface{}, comparator Comparator) (Block, error) {
	if b.readerat == nil {
		return nil, errors.New("The underlying storage is not capable " +
			"of performing random reads")
	}

	left := uint32(0)
	right, err := b.GetTotalBlocks()
	if err != nil {
		return nil, errors.New(err)
	}
	right--

	for true {
		mid := (left + right) / 2
		block, err := b.ReadBlockAt(mid)
		if err != nil {
			return nil, errors.New(err)
		}

		comp, err := comparator(value, block)
		if err != nil {
			return nil, errors.New(err)
		}
		// Found
		if comp == 1 {
			return block, nil
		}
		// Doesn't exist
		if comp == 0 {
			return nil, nil
		}

		// Can't find the value
		if left == right {
			return nil, nil
		}

		if comp < 0 {
			if mid > left {
				right = mid - 1
			} else {
				right = left
			}
		} else {
			if mid < right {
				left = mid + 1
			} else {
				left = right
			}
		}
	}

	return nil, nil
}

func newBlock(id, size uint32, data []byte) *blockV1 {
	return &blockV1{id, size, data}
}

func (b *blockV1) GetID() uint32 {
	return b.id
}

func (b *blockV1) GetSize() uint32 {
	return b.size
}

func (b *blockV1) GetData() []byte {
	return b.data
}

func (b *blockV1) Serialize(paddedBlockSize uint32) ([]byte, error) {
	blockSize := uint32(len(b.GetData()))
	totalSize := blockHeaderLen + blockSize
	arrayBytes := totalSize

	// Padding turned on
	if paddedBlockSize > 0 {
		arrayBytes = paddedBlockSize

		// Each block can be at most "paddedBlockSize"
		if totalSize > paddedBlockSize {
			return nil, NewBlockPaddingError(
				"Block too large to pad to a fixed size",
				paddedBlockSize, totalSize, paddedBlockSize-8)
		}
	}

	serial := make([]byte, arrayBytes)
	binary.BigEndian.PutUint32(serial[0:], b.GetID())
	binary.BigEndian.PutUint32(serial[blockNumLen:], blockSize)
	copy(serial[blockHeaderLen:], b.GetData())

	// Padding turned on
	if paddedBlockSize > 0 {
		if _, err := rand.Read(serial[totalSize:]); err != nil {
			return nil, errors.New(err)
		}
	}

	return serial, nil
}

func (b *blockV1) deserialize(paddedBlockSize uint32, dataBytes []byte) (*blockV1, error) {
	totalSize := uint32(len(dataBytes))

	if totalSize < blockHeaderLen {
		return nil, errors.Errorf("Insufficient data size of %v", totalSize)
	}

	// Padding turned on
	if paddedBlockSize > 0 && totalSize != paddedBlockSize {
		return nil, errors.Errorf("Data size(%v) does not match padded block size(%v)",
			totalSize, paddedBlockSize)
	}

	b.id = binary.BigEndian.Uint32(dataBytes[0:])
	b.size = binary.BigEndian.Uint32(dataBytes[blockNumLen:])

	if b.size+blockHeaderLen > totalSize {
		return nil, errors.Errorf("Block size(%v) is bigger than the data size(%v)",
			b.size+8, totalSize)
	}

	b.data = dataBytes[blockHeaderLen : blockHeaderLen+b.size]
	return b, nil
}

// DeserializeBlockV1 deserializes V1 block
func DeserializeBlockV1(paddedBlockSize uint32, dataBytes []byte) (Block, error) {
	block := &blockV1{}
	return block.deserialize(paddedBlockSize, dataBytes)
}
