package headers

import (
	"os"
	"testing"

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

func TestPlaintextHeaderV1(t *testing.T) {
	version := PlainHeaderV1

	for _, hdrType := range HeaderTypes {
		plainHdr := &PlainHdrV1{version, hdrType,
			uint32(len(teststr)), []byte(teststr)}

		var header Header = plainHdr
		assert.Equal(t, version, header.GetVersion())

		s, err := header.Serialize()
		assert.NilError(t, err)

		complete, parsedBytes, d, err := DeserializePlainHdrV1(s)
		assert.NilError(t, err)
		assert.Equal(t, complete, true)
		assert.Equal(t, parsedBytes, uint32(len(s)))
		assert.DeepEqual(t, d, plainHdr)
	}
}

func TestCiphertextHeaderV1(t *testing.T) {
	version := CipherHeaderV1

	for _, hdrType := range HeaderTypes {
		cipherHdr := &CipherHdrV1{version, CipherHdrV1Prime,
			hdrType, uint32(len(teststr)), []byte(teststr)}

		var header Header = cipherHdr
		assert.Equal(t, version, header.GetVersion())

		s, err := header.Serialize()
		assert.NilError(t, err)

		complete, parsedBytes, d, err := DeserializeCipherHdrV1(s)
		assert.NilError(t, err)
		assert.Equal(t, complete, true)
		assert.Equal(t, parsedBytes, uint32(len(s)))
		assert.DeepEqual(t, d, cipherHdr)
	}
}

func TestPlaintextCiphtextHeaderStreamV1(t *testing.T) {
	filename := "/tmp/plainciphertextheader"

	for _, hdrType := range HeaderTypes {
		file, err := os.Create(filename)
		assert.NilError(t, err)
		defer os.Remove(filename)
		defer file.Close()

		var header Header

		plainHdr := &PlainHdrV1{PlainHeaderV1, hdrType,
			uint32(len(teststr)), []byte(teststr)}
		header = plainHdr
		assert.Equal(t, PlainHeaderV1, header.GetVersion())

		plainSerial, err := header.Serialize()
		assert.NilError(t, err)

		n, err := file.Write(plainSerial)
		assert.NilError(t, err)
		assert.Equal(t, n, len(plainSerial))

		cipherHdr := &CipherHdrV1{CipherHeaderV1, CipherHdrV1Prime,
			hdrType, uint32(len(teststr)), []byte(teststr)}

		header = cipherHdr
		assert.Equal(t, CipherHeaderV1, header.GetVersion())

		cipherSerial, err := header.Serialize()
		assert.NilError(t, err)

		n, err = file.Write(cipherSerial)
		assert.NilError(t, err)
		assert.Equal(t, n, len(cipherSerial))

		file.Close()

		file, err = os.Open(filename)
		assert.NilError(t, err)

		var parsed uint32

		header, parsed, err = DeserializePlainHdrStream(file)
		assert.NilError(t, err)
		assert.Equal(t, header.GetVersion(), PlainHeaderV1)
		assert.Equal(t, parsed, uint32(len(plainSerial)))

		plainHdr, ok := header.(*PlainHdrV1)
		assert.Assert(t, ok)
		assert.Equal(t, plainHdr.GetVersion(), PlainHeaderV1)
		assert.Equal(t, plainHdr.HdrType, hdrType)
		assert.Equal(t, plainHdr.HdrLen, uint32(len(teststr)))
		assert.DeepEqual(t, plainHdr.HdrBody, []byte(teststr))

		header, parsed, err = DeserializeCipherHdrStream(file)
		assert.NilError(t, err)
		assert.Equal(t, header.GetVersion(), CipherHeaderV1)
		assert.Equal(t, parsed, uint32(len(cipherSerial)))

		cipherHdr, ok = header.(*CipherHdrV1)
		assert.Assert(t, ok)
		assert.Equal(t, cipherHdr.GetVersion(), CipherHeaderV1)
		assert.Equal(t, cipherHdr.Prime, uint32(CipherHdrV1Prime))
		assert.Equal(t, cipherHdr.HdrType, hdrType)
		assert.Equal(t, cipherHdr.HdrLen, uint32(len(teststr)))
		assert.DeepEqual(t, cipherHdr.HdrBody, []byte(teststr))
	}
}
