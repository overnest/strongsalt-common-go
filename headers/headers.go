package headers

import (
	"encoding/binary"
	"io"
	"unsafe"

	"github.com/go-errors/errors"
)

//
// All headers will begin with a 4 byte version number. This version
// number will tell us how to parse the following bytes.
//

// Header is an interface for all header structures with a version number
type Header interface {
	GetVersion() uint32
	Serialize() ([]byte, error)
	GetBody() ([]byte, error)
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

const (
	_ = iota // Skip 0
	// PlainHeaderV1 is plaintext header version 1
	PlainHeaderV1 = uint32(iota)

	// PlainHeaderCurV is the current version of plaintext header
	PlainHeaderCurV = PlainHeaderV1
)

const (
	_ = iota // Skip 0
	// CipherHeaderV1 is ciphertext header version 1
	CipherHeaderV1 = uint32(iota)

	// CipherHeaderCurV is the current version of ciphertext header
	CipherHeaderCurV = CipherHeaderV1
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

// Our headers have variable lengths. Therefore, when deserializing, we
// will not know ahead of time how many bytes to pass to the deserialization
// function. The only way to know whether we have enough bytes for deserialization
// is to attempt deserialization. So we will have the following return values
// for all deserialization functions:
// 1. complete: whether the passed in byte array is enough to deserialize the
// 			 entire header. If complete = false, then the user needs to
// 			 retry the function with more bytes.
// 2. parsedBytes: if complete = true, then this field tells the caller how
// 			 many bytes of the input array was actually used. The rest
// 			 of the array would be part of the data that follows this
// 			 header.
// 3. header: if complete = true, this would be the deserialized header object
// 4. err: unrecoverable error occurred during the deserialization process.
//      No need to reattempt. Not having enough bytes in the input array will
// 		NEVER generate an error.

// DeserializePlainHdr is the deserialization function for plaintext header
func DeserializePlainHdr(b []byte) (complete bool, parsedBytes uint32, header Header, err error) {
	complete = false
	parsedBytes = 0
	header = nil
	err = nil

	if len(b) < 4 {
		return
	}

	version := binary.BigEndian.Uint32(b[0:])
	parsedBytes += uint32(unsafe.Sizeof(version))

	switch version {
	case PlainHeaderV1:
		return DeserializePlainHdrV1(b)
	}

	err = errors.Errorf("Version %v is not supported", version)
	return
}

// DeserializePlainHdrStream is the deserialization function for plaintext header
func DeserializePlainHdrStream(reader io.Reader) (header Header, parsed uint32, err error) {
	header = nil
	parsed = 0
	err = nil

	var version uint32
	if err = binary.Read(reader, binary.BigEndian, &version); err != nil {
		err = errors.WrapPrefix(err, "Can not read version number", 1)
		return
	}

	switch version {
	case PlainHeaderV1:
		header, parsed, err = DeserializePlainHdrStreamV1(reader)
		parsed += 4
		return
	default:
		err = errors.Errorf("Version %v is not supported", version)
		return
	}
}

// DeserializeCipherHdr is the deserialization function for ciphertext header
func DeserializeCipherHdr(b []byte) (complete bool, parsedBytes uint32, header Header, err error) {
	complete = false
	parsedBytes = 0
	header = nil
	err = nil

	if len(b) < 4 {
		return
	}

	version := binary.BigEndian.Uint32(b[0:])
	parsedBytes += uint32(unsafe.Sizeof(version))

	switch version {
	case CipherHeaderV1:
		return DeserializeCipherHdrV1(b)
	}

	err = errors.Errorf("Version %v is not supported", version)
	return
}

// DeserializeCipherHdrStream is the deserialization function for ciphertext header
func DeserializeCipherHdrStream(reader io.Reader) (header Header, parsed uint32, err error) {
	header = nil
	parsed = 0
	err = nil

	var version uint32
	if err = binary.Read(reader, binary.BigEndian, &version); err != nil {
		err = errors.WrapPrefix(err, "Can not read version number", 1)
		return
	}

	switch version {
	case CipherHeaderV1:
		header, parsed, err = DeserializeCipherHdrStreamV1(reader)
		parsed += 4
		return
	default:
		err = errors.Errorf("Version %v is not supported", version)
		return
	}
}
