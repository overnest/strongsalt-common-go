package tools

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"

	"github.com/go-errors/errors"
)

// Gzip compresses some bytes
func Gzip(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, errors.New(err)
	}
	if err := zw.Close(); err != nil {
		return nil, errors.New(err)
	}
	zb, err := ioutil.ReadAll(&buf)
	if err != nil {
		return nil, errors.New(err)
	}
	return zb, nil
}

// Gunzip uncompresses some bytes
func Gunzip(zb []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(zb))
	if err != nil {
		return nil, errors.New(err)
	}

	b, err := ioutil.ReadAll(zr)
	if err != nil {
		zr.Close()
		return nil, errors.New(err)
	}

	zr.Close()
	return b, nil
}
