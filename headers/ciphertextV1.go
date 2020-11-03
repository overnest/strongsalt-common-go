package headers

import (
	"encoding/binary"
	"fmt"

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

func (h *CipherHdrV1) deserialize(b []byte) error {
	if len(b) < 16 {
		return errors.New(fmt.Sprintf(
			"Parsing error. Insufficient input byte count of %v", len(b)))
	}

	h.Version = binary.BigEndian.Uint32(b[0:])
	h.Prime = binary.BigEndian.Uint32(b[4:])
	if h.Prime != CipherHdrV1Prime {
		return errors.New(fmt.Sprintf(
			"Parsing error. Prime number does not match. Possible corruption"))
	}

	h.HdrType = HeaderType(binary.BigEndian.Uint32(b[8:]))
	h.HdrLen = binary.BigEndian.Uint32(b[12:])
	if uint32(len(b)) < 16+h.HdrLen {
		return errors.New(fmt.Sprintf(
			"Parsing error. Expecting %v bytes but only received %v",
			16+h.HdrLen, len(b)))
	}

	h.HdrBody = b[16 : 16+h.HdrLen]
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

// DeserializeCipherHdrV1 deserializes the ciphertext header
func DeserializeCipherHdrV1(b []byte) (*CipherHdrV1, error) {
	h := &CipherHdrV1{}
	if err := h.deserialize(b); err != nil {
		return nil, err
	}
	return h, nil
}
