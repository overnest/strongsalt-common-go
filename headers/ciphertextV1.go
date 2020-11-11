package headers

import (
	"encoding/binary"

	"github.com/go-errors/errors"
	"github.com/overnest/strongsalt-common-go/tools"
)

const (
	// CipherHdrV1Prime is a prime number used to detect decryption error
	CipherHdrV1Prime = 1879785779
)

const (
	_ = iota // Skip 0
	// CipherHeaderV1 is ciphertext header version 1
	CipherHeaderV1 = uint32(iota)

	// CipherHeaderCurV is the current version of ciphertext header
	CipherHeaderCurV = CipherHeaderV1
)

// The ciphertext header V1 has the following format:
// -------------------------------------------------------------------
// | version(4) | prime(4) | hdrtype(4) | hdrlen(4) | header(hdrlen) |
// -------------------------------------------------------------------
// 1. version(4 bytes): This tells us which header version to use when
// 	  parsing.
// 2. prime(4 bytes): This allows us to quickly detect whether we're
// 	  dealing with data that we encrypted. It's highly unlikely that our
// 	  exact prime number number would occur if the original data wasn't
//    encrypted by us.
// 3. hdrtype(4 bytes): Format of the header that follows
// 4. hdrlen(4 bytes): This tells us how many bytes the serialized headers
//    are.
// 5. header(hdrlen bytes): The serialized header information

// CipherHdrV1 is the V1 plaintext header
type CipherHdrV1 struct {
	Version uint32
	Prime   uint32
	HdrType HeaderType
	HdrLen  uint32
	HdrBody []byte
}

// GetVersion retrieves the version number
func (h *CipherHdrV1) GetVersion() uint32 {
	return h.Version
}

// Serialize serializes the ciphertext header
func (h *CipherHdrV1) Serialize() ([]byte, error) {
	body := h.HdrBody
	if h.HdrType.IsGzipped() {
		var err error
		if body, err = tools.Gzip(h.HdrBody); err != nil {
			return nil, errors.New(err)
		}
	}

	b := make([]byte, 4+4+4+4+len(body))
	binary.BigEndian.PutUint32(b[0:], h.Version)
	binary.BigEndian.PutUint32(b[4:], h.Prime)
	binary.BigEndian.PutUint32(b[8:], uint32(h.HdrType))

	binary.BigEndian.PutUint32(b[12:], uint32(len(body)))
	copy(b[16:], body)
	return b, nil
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
// 3. err: unrecoverable error occurred during the deserialization process.
//      No need to reattempt. Not having enough bytes in the input array will
// 		NEVER generate an error.

func (h *CipherHdrV1) deserialize(b []byte) (complete bool, parsedBytes uint32, err error) {
	complete = false
	parsedBytes = 0
	err = nil

	if len(b) < 16 {
		return
	}

	h.Version = binary.BigEndian.Uint32(b[0:])
	h.Prime = binary.BigEndian.Uint32(b[4:])
	parsedBytes += 8

	if h.Prime != CipherHdrV1Prime {
		err = errors.Errorf("Parsing error. Prime number does not match. Possible corruption")
		return
	}

	h.HdrType = HeaderType(binary.BigEndian.Uint32(b[8:]))
	h.HdrLen = binary.BigEndian.Uint32(b[12:])
	parsedBytes += 8

	if uint32(len(b)) < parsedBytes+h.HdrLen {
		return
	}

	h.HdrBody = b[parsedBytes : parsedBytes+h.HdrLen]
	parsedBytes += h.HdrLen

	if h.HdrType.IsGzipped() {
		body, gerr := tools.Gunzip(h.HdrBody)
		if gerr != nil {
			err = errors.New(gerr)
			return
		}
		h.HdrLen = uint32(len(body))
		h.HdrBody = body
	}

	complete = true
	return
}

// DeserializeCipherHdrV1 deserializes the ciphertext header
func DeserializeCipherHdrV1(b []byte) (complete bool, parsedBytes uint32, header *CipherHdrV1, err error) {
	complete = false
	parsedBytes = 0
	header = nil
	err = nil

	header = &CipherHdrV1{}
	if complete, parsedBytes, err = header.deserialize(b); err != nil {
		return
	}
	return
}
