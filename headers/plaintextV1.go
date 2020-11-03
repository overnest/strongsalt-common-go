package headers

import (
	"encoding/binary"
	"fmt"

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

func (h *PlainHdrV1) deserialize(b []byte) error {
	if len(b) < 12 {
		return errors.New(fmt.Sprintf(
			"Parsing error. Insufficient input byte count of %v", len(b)))
	}

	h.Version = binary.BigEndian.Uint32(b[0:])
	h.HdrType = HeaderType(binary.BigEndian.Uint32(b[4:]))
	h.HdrLen = binary.BigEndian.Uint32(b[8:])

	if uint32(len(b)) < 12+h.HdrLen {
		return errors.New(fmt.Sprintf(
			"Parsing error. Expecting %v bytes but only received %v",
			12+h.HdrLen, len(b)))
	}

	h.HdrBody = b[12 : 12+h.HdrLen]
	if h.HdrType.IsGzipped() {
		body, err := tools.Gunzip(h.HdrBody)
		if err != nil {
			return errors.New(err)
		}
		h.HdrLen = uint32(len(body))
		h.HdrBody = body
	}

	return nil
}

// DeserializePlainHdrV1 deserializes the plaintext header
func DeserializePlainHdrV1(b []byte) (*PlainHdrV1, error) {
	h := &PlainHdrV1{}
	if err := h.deserialize(b); err != nil {
		return nil, err
	}
	return h, nil
}
