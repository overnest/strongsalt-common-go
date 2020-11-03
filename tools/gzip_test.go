package tools

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

func TestGzip(t *testing.T) {
	zb, err := Gzip([]byte(teststr))
	assert.NilError(t, err)
	b, err := Gunzip(zb)
	assert.NilError(t, err)
	assert.Equal(t, teststr, string(b))

	zb, err = Gzip(nil)
	assert.NilError(t, err)
	b, err = Gunzip(zb)
	assert.NilError(t, err)
	assert.Equal(t, len(b), 0)
}
