package torcert

import (
	"encoding/binary"
	"io"
)

var ExtRegistry = make(map[EXT_TYPE]func() Extension)

func NewExtension(extType EXT_TYPE) (ext Extension) {
	if extFn := ExtRegistry[extType]; extFn != nil {
		ext = extFn()
	} else {
		ext = &UnknownExtension{}
	}
	return
}

type Extension interface {
	// Basic methods
	ExtType() EXT_TYPE
	ExtSize() int
	ExtFlags() EXT_FLAG
	ExtSetType(extType EXT_TYPE)
	ExtSetFlags(extFlags EXT_FLAG)

	// I/O methods
	ExtUpdate() int
	ExtRead(r io.Reader, header *ExtHeader) (err error)
	ExtWrite(w io.Writer) (err error)
}

type ExtHeader struct {
	Length uint16
	Type   EXT_TYPE
	Flags  EXT_FLAG
}

var _ Extension = (*ExtHeader)(nil)

func (h ExtHeader) ExtType() EXT_TYPE {
	return h.Type
}

func (h ExtHeader) ExtSize() int {
	return 4 + int(h.Length)
}

func (h ExtHeader) ExtFlags() EXT_FLAG {
	return h.Flags
}

func (h *ExtHeader) ExtSetType(extType EXT_TYPE) {
	h.Type = extType
}

func (h *ExtHeader) ExtSetFlags(extFlags EXT_FLAG) {
	h.Flags = extFlags
}

func (h *ExtHeader) ExtUpdate() int {
	return h.ExtSize()
}

func (h *ExtHeader) ExtRead(r io.Reader, header *ExtHeader) (err error) {
	if header == nil {
		if err = binary.Read(r, binary.BigEndian, &h.Length); err != nil {
			return
		}
		if err = binary.Read(r, binary.BigEndian, &h.Type); err != nil {
			return
		}
		if err = binary.Read(r, binary.BigEndian, &h.Flags); err != nil {
			return
		}
	} else {
		*h = *header
	}
	return
}

func (h ExtHeader) ExtWrite(w io.Writer) (err error) {
	if err = binary.Write(w, binary.BigEndian, h.Length); err != nil {
		return
	}
	if err = binary.Write(w, binary.BigEndian, h.Type); err != nil {
		return
	}
	if err = binary.Write(w, binary.BigEndian, h.Flags); err != nil {
		return
	}
	return
}

type EXT_TYPE uint8

const (
	EXT_TYPE_ED25519_SIGNING_KEY EXT_TYPE = 0x04
)

type EXT_FLAG uint8

const (
	EXT_FLAG_INCLUDE_SIGNING_KEY EXT_FLAG = 0x01
)
