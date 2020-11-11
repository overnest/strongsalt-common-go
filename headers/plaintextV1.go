package headers

import (
	"encoding/binary"

	"github.com/go-errors/errors"
	"github.com/overnest/strongsalt-common-go/tools"
)

const (
	_ = iota // Skip 0
	// PlainHeaderV1 is plaintext header version 1
	PlainHeaderV1 = uint32(iota)

	// PlainHeaderCurV is the current version of plaintext header
	PlainHeaderCurV = PlainHeaderV1
)

// The plaintext header V1 has the following format:
// --------------------------------------------------------
// | version(4) | hdrtype(4) | hdrlen(4) | header(hdrlen) |
// --------------------------------------------------------
// 1. version(4 bytes): This tells us which header version to use when
// 	  parsing.
// 2. hdrtype(4 bytes): Format of the header that follows
// 3. hdrlen(4 bytes): This tells us how many bytes the serialized headers
//    are.
// 4. header(hdrlen bytes): The serialized header information

// PlainHdrV1 is the V1 plaintext header
type PlainHdrV1 struct {
	Version uint32
	HdrType HeaderType
	HdrLen  uint32
	HdrBody []byte
}

// GetVersion retrieves the version number
func (h *PlainHdrV1) GetVersion() uint32 {
	return h.Version
}

// Serialize serializes the plaintext header
func (h *PlainHdrV1) Serialize() ([]byte, error) {
	body := h.HdrBody
	if h.HdrType.IsGzipped() {
		var err error
		if body, err = tools.Gzip(h.HdrBody); err != nil {
			return nil, errors.New(err)
		}
	}

	b := make([]byte, 4+4+4+len(body))
	binary.BigEndian.PutUint32(b[0:], h.Version)
	binary.BigEndian.PutUint32(b[4:], uint32(h.HdrType))
	binary.BigEndian.PutUint32(b[8:], uint32(len(body)))
	copy(b[12:], body)
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

func (h *PlainHdrV1) deserialize(b []byte) (complete bool, parsedBytes uint32, err error) {
	complete = false
	parsedBytes = 0
	err = nil

	if len(b) < 12 {
		return
	}

	h.Version = binary.BigEndian.Uint32(b[0:])
	h.HdrType = HeaderType(binary.BigEndian.Uint32(b[4:]))
	h.HdrLen = binary.BigEndian.Uint32(b[8:])
	parsedBytes += 12

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

// DeserializePlainHdrV1 deserializes the plaintext header
func DeserializePlainHdrV1(b []byte) (complete bool, parsedBytes uint32, header *PlainHdrV1, err error) {
	complete = false
	parsedBytes = 0
	header = nil
	err = nil

	header = &PlainHdrV1{}
	if complete, parsedBytes, err = header.deserialize(b); err != nil {
		return
	}
	return
}
