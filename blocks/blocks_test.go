package blocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"

	"github.com/go-errors/errors"
	"github.com/google/go-cmp/cmp"
	"github.com/overnest/strongsalt-common-go/tools"
	"gotest.tools/assert"
)

const teststr = `Calling Multistream(false) disables this behavior; disabling 
the behavior can be useful when reading file formats that distinguish 
individual gzip data streams or mix gzip data streams with other data 
streams. In this mode, when the Reader reaches the end of the data stream, 
Read returns io.EOF. The underlying reader must implement io.ByteReader 
in order to be left positioned just after the gzip stream. To start the 
next stream, call z.Reset(r) followed by z.Multistream(false). If there 
is no next stream, z.Reset(r) will return io.EOF.`

func TestBlockV1(t *testing.T) {
	hdrSize := uint32(8)
	data := []byte(teststr)
	dataSize := uint32(30)

	block := newBlock(1, dataSize, data[:dataSize])

	paddedSizes := []uint32{
		dataSize + hdrSize,
		dataSize + hdrSize + 10,
		dataSize + hdrSize + 100,
		dataSize + hdrSize - 10,
		0,
	}

	for _, paddedBlockSize := range paddedSizes {
		serial, err := block.Serialize(paddedBlockSize)

		if paddedBlockSize > 0 { // Fix sized blocks are turned on
			if paddedBlockSize < dataSize+hdrSize {
				assert.ErrorType(t, err, &BlockPaddingError{})
				if paderr, ok := err.(*BlockPaddingError); !ok {
					// Should never get here
					assert.Assert(t, ok)
				} else {
					assert.Equal(t, paderr.BlockSize, dataSize+hdrSize)
					assert.Equal(t, paderr.PaddedBlockSize, paddedBlockSize)
				}
			} else {
				assert.NilError(t, err)
				assert.Equal(t, uint32(len(serial)), paddedBlockSize)
				assert.DeepEqual(t, block.GetData(), serial[hdrSize:hdrSize+dataSize])

				deserialBlock, err := DeserializeBlockV1(paddedBlockSize, serial)
				assert.NilError(t, err)
				assert.DeepEqual(t, block, deserialBlock, cmp.AllowUnexported(blockV1{}))
			}
		} else { // Fix sized blocks are turned off
			assert.NilError(t, err)
			assert.Equal(t, uint32(len(serial)), dataSize+hdrSize)
			assert.DeepEqual(t, block.GetData(), serial[hdrSize:])

			deserialBlock, err := DeserializeBlockV1(paddedBlockSize, serial)
			assert.NilError(t, err)
			assert.DeepEqual(t, block, deserialBlock, cmp.AllowUnexported(blockV1{}))
		}
	} // for _, paddedBlockSize := range paddedSizes
}

func TestBlockListV1(t *testing.T) {
	// Test variable sized block list
	testBlockListV1(t, 0, 10, 50, 0)
	testBlockListV1(t, 0, 10, 50, 100)
	// Test padded fixed sized block list
	testBlockListV1(t, 15, 10, 50, 0)
	testBlockListV1(t, 15, 10, 50, 100)
}

func testBlockListV1(t *testing.T, paddedBlockSize, targetBlockSize, variancePercentage uint32, initOffset uint64) {
	fileName := "/tmp/blocklistv1_test"

	//
	// Create block list
	//
	file, err := os.Create(fileName)
	assert.NilError(t, err)
	defer os.Remove(fileName)
	defer file.Close()

	if initOffset > 0 {
		garbage := make([]byte, initOffset)
		n, err := rand.Read(garbage)
		assert.NilError(t, err)
		assert.Equal(t, n, len(garbage))
		n, err = file.Write(garbage)
		assert.NilError(t, err)
		assert.Equal(t, n, len(garbage))
	}

	blWriter, err := NewBlockListWriterV1(file, paddedBlockSize, initOffset)
	assert.NilError(t, err)
	assert.Equal(t, blWriter.GetVersion(), BlockListV1)

	// bl, err := NewBlockListWriter(file, fixedBlockSize)
	// assert.NilError(t, err)
	// assert.Equal(t, bl.GetVersion(), BlockListV1)
	// blWriter, ok := bl.(BlockListWriterV1)
	// assert.Assert(t, ok)

	assert.Equal(t, blWriter.GetPaddedBlockSize(), paddedBlockSize)
	totalBlocks, err := blWriter.GetTotalBlocks()

	if paddedBlockSize > 0 {
		assert.Assert(t, blWriter.IsBlockPadded())
		assert.NilError(t, err)
		assert.Equal(t, totalBlocks, uint32(0))
	} else {
		assert.Assert(t, !blWriter.IsBlockPadded())
		assert.Assert(t, err != nil)
	}

	varianceByteRange := int((targetBlockSize * variancePercentage / 100))
	buffer := bytes.NewBufferString(teststr)
	var n int = 0
	err = nil
	writtenBlocks := uint32(0)

	for err == nil {
		var block Block
		blockData := getVariableSizedBlocks(varianceByteRange, targetBlockSize)
		n, err = buffer.Read(blockData)
		if err == nil {
			blockData = blockData[:n]
			blockDataLen := uint32(len(blockData))

			block, err = blWriter.WriteBlockData(blockData)
			if blWriter.IsBlockPadded() {
				if blockDataLen > blWriter.GetPaddedBlockSize()-8 {
					// Too big to be padded
					_, ok := IsBlockPaddingError(err)
					assert.Assert(t, ok)

					for blockDataLen > 0 {
						maxDataSize := tools.MinUint32(blWriter.GetMaxDataSize(), uint32(len(blockData)))
						block, err = blWriter.WriteBlockData(blockData[:maxDataSize])
						assert.NilError(t, err)
						assert.Equal(t, block.GetSize(), uint32(len(blockData[:maxDataSize])))
						assert.DeepEqual(t, block.GetData(), blockData[:maxDataSize])
						blockData = blockData[maxDataSize:]
						blockDataLen = uint32(len(blockData))
						writtenBlocks++
					}
				} else {
					assert.Equal(t, block.GetSize(), blockDataLen)
					assert.DeepEqual(t, block.GetData(), blockData)
					writtenBlocks++
				}
			} else {
				assert.NilError(t, err)
				assert.Equal(t, block.GetSize(), uint32(len(blockData)))
				assert.DeepEqual(t, block.GetData(), blockData)
				writtenBlocks++
			}
		}
	}

	file.Close()

	//
	// Read block list serially
	//
	file, err = os.Open(fileName)
	assert.NilError(t, err)
	defer file.Close()
	stat, err := file.Stat()
	assert.NilError(t, err)

	if initOffset > 0 {
		garbage := make([]byte, initOffset)
		n, err = file.Read(garbage)
		assert.NilError(t, err)
		assert.Equal(t, n, len(garbage))
	}

	blReader, err := NewBlockListReaderV1(file, initOffset, uint64(stat.Size()))
	assert.NilError(t, err)
	readBlocks := uint32(0)

	//
	// Read block list serially
	//
	var readBytes []byte = nil
	err = nil
	for err == nil {
		var block Block
		block, err = blReader.ReadNextBlock()
		if err == nil {
			assert.Equal(t, block.GetSize(), uint32(len(block.GetData())))
			assert.DeepEqual(t, block.GetData(), blReader.GetCurBlock().GetData())
			readBytes = append(readBytes, block.GetData()...)
			readBlocks++
		} else {
			assert.Equal(t, err, io.EOF)
		}
	}

	assert.Equal(t, readBlocks, writtenBlocks)
	assert.Equal(t, teststr, string(readBytes))

	//
	// Read block list randomly
	//
	readBytes = nil
	readBlocks = 0
	if blReader.IsBlockPadded() {
		totalBlocks, err := blReader.GetTotalBlocks()
		assert.NilError(t, err)
		for i := int(totalBlocks) - 1; i >= 0; i-- {
			block, err := blReader.ReadBlockAt(uint32(i))
			assert.NilError(t, err)
			readBytes = append(block.GetData(), readBytes...)
			readBlocks++
		}

		assert.Equal(t, readBlocks, writtenBlocks)
		assert.Equal(t, teststr, string(readBytes))
	}
}

func getVariableSizedBlocks(varianceByteRange int, targetBlockSize uint32) []byte {
	varianceBytes := uint32(rand.Intn(varianceByteRange))
	blockSize := targetBlockSize
	if int(varianceBytes) < varianceByteRange/2 {
		blockSize -= varianceBytes
	} else {
		blockSize += varianceBytes
	}

	return make([]byte, blockSize)
}

func TestBlockListSerachV1(t *testing.T) {
	testBlockListSearchV1(t, false, 0)
}

func testBlockListSearchV1(t *testing.T, padded bool, initOffset uint64) {
	fileName := "/tmp/blocklistsearchv1_test"
	paddedBlockSize := uint32(1024 * 1)
	start := uint64(10)
	end := uint64(100000)

	//
	// Create block list
	//
	file, err := os.Create(fileName)
	assert.NilError(t, err)
	defer os.Remove(fileName)
	defer file.Close()

	if initOffset > 0 {
		garbage := make([]byte, initOffset)
		n, err := rand.Read(garbage)
		assert.NilError(t, err)
		assert.Equal(t, n, len(garbage))
		n, err = file.Write(garbage)
		assert.NilError(t, err)
		assert.Equal(t, n, len(garbage))
	}

	blWriter, err := NewBlockListWriterV1(file, paddedBlockSize, initOffset)
	assert.NilError(t, err)
	assert.Equal(t, blWriter.GetVersion(), BlockListV1)

	var block *testBlockV1 = &testBlockV1{List: make([]uint64, 0, 100)}
	for i := start; i < end; i++ {
		value := i * 10
		block.List = append(block.List, value)
		serial, err := block.Serialize()
		assert.NilError(t, err)

		if uint32(len(serial)) > blWriter.GetMaxDataSize() {
			block.List = block.List[:len(block.List)-1]
			serial, err = block.Serialize()
			assert.NilError(t, err)
			_, err = blWriter.WriteBlockData(serial)
			assert.NilError(t, err)

			block = &testBlockV1{List: make([]uint64, 0, 100)}
			block.List = append(block.List, value)
		}
	}

	if len(block.List) > 0 {
		serial, err := block.Serialize()
		assert.NilError(t, err)
		_, err = blWriter.WriteBlockData(serial)
		assert.NilError(t, err)
	}

	file.Close()

	//
	// Open block list
	//
	file, err = os.Open(fileName)
	assert.NilError(t, err)
	defer file.Close()
	stat, err := file.Stat()
	assert.NilError(t, err)

	if initOffset > 0 {
		garbage := make([]byte, initOffset)
		n, err := file.Read(garbage)
		assert.NilError(t, err)
		assert.Equal(t, n, len(garbage))
	}

	blReader, err := NewBlockListReaderV1(file, initOffset, uint64(stat.Size()))
	assert.NilError(t, err)

	//
	// Search
	//
	// These should not be found
	// 1. lower than the start value
	// 2. higher than end value
	// 3. anything not divisible by 10
	v := start - 1
	for i := 0; i < 100 && v > 0; i++ {
		testSearchV1(t, v*10, false, blReader)
		v--
	}

	v = end + 1
	for i := 0; i < 100; i++ {
		testSearchV1(t, v*10, false, blReader)
		v++
	}

	for i := 0; i < 100; i++ {
		v := uint64(rand.Int63n(int64(end-start))) + start
		testSearchV1(t, (v*10)+5, false, blReader)
	}

	// These should be found
	for i := 0; i < 100; i++ {
		v := uint64(rand.Int63n(int64(end-start))) + start
		testSearchV1(t, v*10, true, blReader)
	}
}

func testSearchV1(t *testing.T, value uint64, shouldExist bool, blReader BlockListReaderV1) {
	blk, err := blReader.SearchLinear(value, BlockTestComparator)
	assert.NilError(t, err)
	if shouldExist {
		assert.Assert(t, blk != nil)
	} else {
		assert.Equal(t, blk, nil)
	}

	blk, err = blReader.SearchBinary(value, BlockTestComparator)
	if err != nil {
		fmt.Println(value, err.(*errors.Error).ErrorStack())
	}
	assert.NilError(t, err)
	if shouldExist {
		assert.Assert(t, blk != nil)
	} else {
		assert.Equal(t, blk, nil)
	}
}

type testBlockV1 struct {
	List []uint64
}

func (block *testBlockV1) Serialize() ([]byte, error) {
	b, err := json.Marshal(block)
	if err != nil {
		return nil, errors.New(err)
	}
	return b, nil
}

func (block *testBlockV1) Deserialize(data []byte) (*testBlockV1, error) {
	err := json.Unmarshal(data, block)
	if err != nil {
		return nil, errors.New(err)
	}

	return block, nil
}

func BlockTestComparator(value interface{}, block Block) (int, error) {
	val, ok := value.(uint64)
	if !ok {
		return 0, errors.Errorf("The value is not uint64")
	}

	blk := &testBlockV1{}
	blk, err := blk.Deserialize(block.GetData())
	if err != nil {
		return 0, errors.New(err)
	}

	if val < blk.List[0] {
		return -1, nil
	}

	if val > blk.List[len(blk.List)-1] {
		return 2, nil
	}

	for _, v := range blk.List {
		if val == v {
			return 1, nil
		}
	}

	return 0, nil
}
