package headers

import (
	"encoding/binary"
	"fmt"

	"github.com/go-errors/errors"
)

// Header is an interface for all header structures with a version number
type Header interface {
	GetVersion() uint32
	Serialize() ([]byte, error)
}

// HeaderVer is structure used to parse header version
type HeaderVer struct {
	Version uint32
}

// GetVersion retrieves the version number
func (h *HeaderVer) GetVersion() uint32 {
	return h.Version
}

// HeaderType is the header body type
type HeaderType int

// Do not ever remove or change the order of HeaderType!!!!
const (
	_ = iota // Skip 0
	// HeaderTypeJSON means header body type is JSON
	HeaderTypeJSON = HeaderType(iota)
	// HeaderTypeJSONGzip means header body type is Gzipped JSON
	HeaderTypeJSONGzip = HeaderType(iota)
	// HeaderTypeBSON means header body type is BSON
	HeaderTypeBSON = HeaderType(iota)
	// HeaderTypeBSONGzip means header body type is Gzipped BSON
	HeaderTypeBSONGzip = HeaderType(iota)
)

// IsGzipped shows whether header is Gzipped
func (t HeaderType) IsGzipped() bool {
	return (t == HeaderTypeJSONGzip || t == HeaderTypeBSONGzip)
}

var (
	// HeaderTypes is the valid list of header types
	HeaderTypes = []HeaderType{
		HeaderTypeJSON, HeaderTypeJSONGzip,
		HeaderTypeBSON, HeaderTypeBSONGzip}
)

// CreatePlainHdr creates a plaintext header
func CreatePlainHdr(hdrType HeaderType, hdrBody []byte) Header {
	hdr := &PlainHdrV1{PlainHeaderV1, hdrType,
		uint32(len(hdrBody)), hdrBody}
	return hdr
}

// CreateCipherHdr creates a ciphertext header
func CreateCipherHdr(hdrType HeaderType, hdrBody []byte) Header {
	hdr := &CipherHdrV1{CipherHeaderV1, CipherHdrV1Prime,
		hdrType, uint32(len(hdrBody)), hdrBody}
	return hdr
}

// DeserializePlainHdr is the deserialization function for plaintext header
func DeserializePlainHdr(b []byte) (Header, error) {
	if len(b) < 4 {
		return nil, errors.New(fmt.Sprintf(
			"Parsing error. Insufficient input byte count of %v", len(b)))
	}

	version := binary.BigEndian.Uint32(b[0:])
	switch version {
	case PlainHeaderV1:
		return DeserializePlainHdrV1(b)
	}

	return nil, errors.New(fmt.Sprintf("Version %v is not supported", version))
}

// DeserializeCipherHdr is the deserialization function for ciphertext header
func DeserializeCipherHdr(b []byte) (Header, error) {
	if len(b) < 4 {
		return nil, errors.New(fmt.Sprintf(
			"Parsing error. Insufficient input byte count of %v", len(b)))
	}

	version := binary.BigEndian.Uint32(b[0:])
	switch version {
	case CipherHeaderV1:
		return DeserializeCipherHdrV1(b)
	}

	return nil, errors.New(fmt.Sprintf("Version %v is not supported", version))
}
