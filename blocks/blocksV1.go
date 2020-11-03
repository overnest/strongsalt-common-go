package blocks

import (
	"encoding/binary"
	"io"
	"math/rand"

	"github.com/go-errors/errors"
)

// BlockListWriterV1 is the block list writer interface for version 1
type BlockListWriterV1 interface {
	GetVersion() uint32
	IsFixedSize() bool
	GetFixedSize() uint32
	WriteBlock(block Block) error
}

// BlockListReaderV1 is the block list reader interface for version 1
type BlockListReaderV1 interface {
	GetVersion() uint32
	IsFixedSize() bool
	GetFixedSize() uint32
	GetTotalBlocks() (uint32, error)
	GetCurBlock() Block
	ReadNextBlock() (Block, error)
	ReadBlockAt(index uint32) (Block, error)
}

type blockListV1 struct {
	version    uint32
	fixedSize  uint32
	curBlock   Block
	writer     io.Writer
	reader     io.Reader
	readerat   io.ReaderAt
	seeker     io.Seeker
	initOffset uint64
	curOffset  uint64
	endOffset  uint64
}

type blockV1 struct {
	id   uint32
	size uint32
	data []byte
}

// NewBlockListWriterV1 creates a block list version 1 writer
func NewBlockListWriterV1(store interface{}, fixedSize uint32) (BlockListWriterV1, error) {
	var ok bool
	b := &blockListV1{BlockListV1, fixedSize, nil, nil, nil, nil, nil, 0, 0, 0}

	if b.writer, ok = store.(io.Writer); !ok {
		return nil, errors.New("The storage must implement io.Writer")
	}

	if b.IsFixedSize() {
		if _, ok = store.(io.ReaderAt); !ok {
			return nil, errors.New(`A fixed size block list allows random access, 
				which requires the storage to implement io.ReaderAt`)
		}
	}

	return b, nil
}

// NewBlockListReaderV1 creates a block list version 1 reader
func NewBlockListReaderV1(store interface{}, initOffset, endOffset uint64) (BlockListReaderV1, error) {
	var ok bool
	b := &blockListV1{BlockListV1, 0, nil, nil, nil, nil, nil, initOffset, initOffset, endOffset}

	if b.reader, ok = store.(io.Reader); !ok {
		return nil, errors.New("The storage must implement io.Reader")
	}

	fixedSize := make([]byte, 4)
	n, err := b.reader.Read(fixedSize)
	if err != nil {
		return nil, errors.New(err)
	}
	if n != len(fixedSize) {
		return nil, errors.New("Can not read block list fixed size data from storage")
	}

	b.fixedSize = binary.BigEndian.Uint32(fixedSize)
	if b.IsFixedSize() {
		if b.readerat, ok = store.(io.ReaderAt); !ok {
			return nil, errors.New(`A fixed size block list allows random access, 
				which requires the storage to implement io.ReaderAt`)
		}

		if endOffset < 1 {
			return nil, errors.New(`A fixed sized block list allows random access, 
				which requires the code to have and endOffset > 0`)
		}

		// We don't necessarily need seek function. But it's nice to have
		if b.seeker, ok = store.(io.Seeker); !ok {
			b.seeker = nil
		}
	}

	return b, nil
}

func (b *blockListV1) GetVersion() uint32 {
	return b.version
}

func (b *blockListV1) IsFixedSize() bool {
	return (b.fixedSize > 0)
}

func (b *blockListV1) GetFixedSize() uint32 {
	return b.fixedSize
}

func (b *blockListV1) checkListValid() error {
	if b.endOffset < b.initOffset {
		return errors.Errorf("The initial offset(%v) of the block list is "+
			"bigger than the end offset(%v)", b.initOffset, b.endOffset)
	}

	if b.IsFixedSize() {
		blockBytes := b.endOffset - b.initOffset
		if blockBytes%uint64(b.GetFixedSize()) > 0 {
			return errors.Errorf("The number of block bytes(%v) does "+
				"not divide evenly by fixed block size(%v).", blockBytes,
				b.GetFixedSize())
		}
	}

	return nil
}

func (b *blockListV1) GetTotalBlocks() (uint32, error) {
	if !b.IsFixedSize() {
		return 0, errors.New("The block list does not have fix sized blocks. " +
			"Can not precalculate total blocks")
	}

	if err := b.checkListValid(); err != nil {
		return 0, err
	}

	blockBytes := b.endOffset - b.initOffset
	return uint32(blockBytes / uint64(b.GetFixedSize())), nil
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

	if b.IsFixedSize() {
		blockBytes = make([]byte, b.GetFixedSize())
		if n, err = b.reader.Read(blockBytes); err != nil {
			return nil, errors.New(err)
		}
		if n != len(blockBytes) {
			return nil, errors.Errorf("Expecting %v bytes but read %v", len(blockBytes), n)
		}
	} else {
		hdr := make([]byte, 8)
		if n, err = b.reader.Read(hdr); err != nil {
			return nil, errors.New(err)
		}
		if n != len(hdr) {
			return nil, errors.Errorf("Expecting %v bytes but read %v", len(hdr), n)
		}

		blockSize := binary.BigEndian.Uint32(hdr[4:])
		blockData := make([]byte, blockSize)
		if n, err = b.reader.Read(blockData); err != nil {
			return nil, errors.New(err)
		}
		if n != len(blockData) {
			return nil, errors.Errorf("Expecting %v bytes but read %v", len(blockData), n)
		}

		blockBytes = append(hdr, blockData...)
		n = len(blockBytes)
	}

	blockv1, err := DeserializeBlockV1(b.GetFixedSize(), blockBytes)
	if err != nil {
		return nil, err
	}

	if b.GetCurBlock() != nil {
		if blockv1.GetID() != b.GetCurBlock().GetID()+1 {
			return nil, errors.Errorf("The next block ID(%v) does not immediately follow "+
				"the previous block ID(%v)", blockv1.GetID(), b.GetCurBlock().GetData())
		}
	}

	b.curOffset += uint64(len(blockBytes))
	b.endOffset = b.curOffset
	b.curBlock = blockv1
	return blockv1, nil
}

func (b *blockListV1) ReadBlockAt(index uint32) (Block, error) {
	if !b.IsFixedSize() {
		return nil, errors.New("The block list does not have fix sized blocks. " +
			"Can not perform random access reads")
	}

	if b.readerat == nil {
		return nil, errors.New("The underlying storage is not capable " +
			"of performing random access reads")
	}

	blockBytes := make([]byte, b.GetFixedSize())
	offset := b.initOffset + (uint64(b.GetFixedSize()) * uint64(index))

	n, err := b.readerat.ReadAt(blockBytes, int64(offset))
	if err != nil {
		return nil, errors.New(err)
	}
	if n != len(blockBytes) {
		return nil, errors.Errorf("Expecting %v bytes but only read %v", len(blockBytes), n)
	}

	block, err := DeserializeBlockV1(b.GetFixedSize(), blockBytes)
	if err != nil {
		return nil, err
	}
	if block.GetID() != index {
		return nil, errors.Errorf("Block ID(%v) does not match the retrieval index(%v)",
			block.GetID(), index)
	}

	return block, nil
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

	serial, err := blockv1.Serialize(b.GetFixedSize())
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

func (b *blockV1) Serialize(fixedSize uint32) ([]byte, error) {
	blockSize := uint32(len(b.GetData()))
	totalSize := 4 + 4 + blockSize
	arrayBytes := totalSize

	// Padding turned on
	if fixedSize > 0 {
		arrayBytes = fixedSize

		// Each block can be at most "fixedSize"
		if totalSize > fixedSize {
			return nil, NewBlockPaddingError(
				"Block too large to pad to a fixed size",
				fixedSize, totalSize)
		}
	}

	serial := make([]byte, arrayBytes)
	binary.BigEndian.PutUint32(serial[0:], b.GetID())
	binary.BigEndian.PutUint32(serial[4:], blockSize)
	copy(serial[8:], b.GetData())

	// Padding turned on
	if fixedSize > 0 {
		if _, err := rand.Read(serial[totalSize:]); err != nil {
			return nil, errors.New(err)
		}
	}

	return serial, nil
}

func (b *blockV1) deserialize(fixedSize uint32, dataBytes []byte) (*blockV1, error) {
	totalSize := uint32(len(dataBytes))

	if totalSize < 8 {
		return nil, errors.Errorf("Insufficient data size of %v", totalSize)
	}

	// Padding turned on
	if fixedSize > 0 && totalSize != fixedSize {
		return nil, errors.Errorf("Data size(%v) does not match fixed block size(%v)",
			totalSize, fixedSize)
	}

	b.id = binary.BigEndian.Uint32(dataBytes[0:])
	b.size = binary.BigEndian.Uint32(dataBytes[4:])

	if b.size+8 > totalSize {
		return nil, errors.Errorf("Block size(%v) is bigger than the data size(%v)",
			b.size+8, totalSize)
	}

	b.data = dataBytes[8 : 8+b.size]
	return b, nil
}

func DeserializeBlockV1(fixedSize uint32, dataBytes []byte) (*blockV1, error) {
	block := &blockV1{}
	return block.deserialize(fixedSize, dataBytes)
}
