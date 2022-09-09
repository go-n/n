package torcert

import "io"

type UnknownExtension struct {
	ExtHeader
	Data []byte
}

var _ Extension = (*UnknownExtension)(nil)

func (ext *UnknownExtension) ExtRead(r io.Reader, header *ExtHeader) (err error) {
	if err = ext.ExtHeader.ExtRead(r, header); err != nil {
		return
	}
	ext.Data = make([]byte, ext.Length)
	readSize, err := io.ReadFull(r, ext.Data)
	if err != nil {
		return
	}
	if readSize < len(ext.Data) {
		err = io.EOF
	}
	return
}

func (ext UnknownExtension) ExtWrite(w io.Writer) (err error) {
	if err = ext.ExtHeader.ExtWrite(w); err != nil {
		return
	}
	if _, err = w.Write(ext.Data); err != nil {
		return
	}
	return
}
