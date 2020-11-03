package headers

import (
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

		d, err := DeserializePlainHdrV1(s)
		assert.NilError(t, err)
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

		d, err := DeserializeCipherHdrV1(s)
		assert.NilError(t, err)
		assert.DeepEqual(t, d, cipherHdr)
	}
}
