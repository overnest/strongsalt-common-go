package blocks

import (
	"math/rand"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
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

	fixesSizes := []uint32{
		dataSize + hdrSize,
		dataSize + hdrSize + 10,
		dataSize + hdrSize + 100,
		dataSize + hdrSize - 10,
		0,
	}

	for _, fixedSize := range fixesSizes {
		serial, err := block.Serialize(fixedSize)

		if fixedSize > 0 { // Fix sized blocks are turned on
			if fixedSize < dataSize+hdrSize {
				assert.ErrorType(t, err, &BlockPaddingError{})
				if paderr, ok := err.(*BlockPaddingError); !ok {
					// Should never get here
					assert.Assert(t, ok)
				} else {
					assert.Equal(t, paderr.BlockSize, dataSize+hdrSize)
					assert.Equal(t, paderr.FixedSize, fixedSize)
				}
			} else {
				assert.NilError(t, err)
				assert.Equal(t, uint32(len(serial)), fixedSize)
				assert.DeepEqual(t, block.GetData(), serial[hdrSize:hdrSize+dataSize])

				deserialBlock, err := DeserializeBlockV1(fixedSize, serial)
				assert.NilError(t, err)
				assert.DeepEqual(t, block, deserialBlock, cmp.AllowUnexported(blockV1{}))
			}
		} else { // Fix sized blocks are turned off
			assert.NilError(t, err)
			assert.Equal(t, uint32(len(serial)), dataSize+hdrSize)
			assert.DeepEqual(t, block.GetData(), serial[hdrSize:])

			deserialBlock, err := DeserializeBlockV1(fixedSize, serial)
			assert.NilError(t, err)
			assert.DeepEqual(t, block, deserialBlock, cmp.AllowUnexported(blockV1{}))
		}
	} // for _, fixedSize := range fixesSizes
}

func TestBlockListV1(t *testing.T) {
	fileName := "/tmp/blocklistv1_test"

	file, err := os.Create(fileName)
	assert.NilError(t, err)
	defer os.Remove(fileName)
	defer file.Close()

	// Test variable sized block list first
	fixedSize := uint32(0)
	targetBlocks := 10
	targetBlockSize := len(teststr) / targetBlocks
	variancePercentage := 50
	varianceByteRange := (targetBlockSize * variancePercentage / 100)

	// blWriter, err := NewBlockListWriterV1(file, fixedSize)
	// assert.NilError(t, err)
	// assert.Equal(t, blWriter.GetVersion(), BlockListV1)

	varianceBytes := rand.Intn(varianceByteRange)
	_ = varianceBytes

	bl, err := NewBlockListWriter(file, fixedSize)
	assert.NilError(t, err)
	assert.Equal(t, bl.GetVersion(), BlockListV1)
	blwriter, ok := bl.(BlockListWriterV1)
	assert.Assert(t, ok)

	assert.Equal(t, blwriter.GetFixedSize(), 0)

}
