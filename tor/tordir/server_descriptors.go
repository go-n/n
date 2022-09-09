package tordir

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ServerDescriptor struct {
	Nickname        string
	Address         string
	ORPort          uint16
	SOCKSPort       uint16
	DirPort         uint16
	IdentityEd25519 []byte
}

type ServerDescriptorReader struct {
	s *bufio.Scanner
}

func NewServerDescriptorReader(r io.Reader) (reader *ServerDescriptorReader) {
	return &ServerDescriptorReader{
		s: bufio.NewScanner(r),
	}
}

func (r *ServerDescriptorReader) Next() (desc *ServerDescriptor, err error) {
	defer func() {
		if err == nil {
			err = r.s.Err()
		}
	}()
	d := &ServerDescriptor{}

	if !r.s.Scan() {
		return
	}
	tokens := strings.Split(r.s.Text(), " ")
	if len(tokens) < 6 {
		err = fmt.Errorf(`[tordir.ServerDescriptor.Next] expects line with 6 tokens: %w`, ErrInvalidFormat)
		return
	}
	if tokens[0] != "router" {
		err = fmt.Errorf(`[tordir.ServerDescriptor.Next] expects line starts with "router": %w`, ErrInvalidFormat)
		return
	}
	d.Nickname, d.Address = tokens[2], tokens[3]
	if d.ORPort, err = parsePort(tokens[4]); err != nil {
		return
	}
	if d.SOCKSPort, err = parsePort(tokens[5]); err != nil {
		return
	}
	if d.DirPort, err = parsePort(tokens[6]); err != nil {
		return
	}

	if !r.s.Scan() {
		return
	}
	if r.s.Text() != "identity-ed25519" {
		err = fmt.Errorf(`[tordir.ServerDescriptor.Next] expects line starts with "identity-ed25519": %w`, ErrInvalidFormat)
		return
	}
	if d.IdentityEd25519, err = scanEd25519Cert(r.s); err != nil {
		return
	}

	desc = d
	return
}

func parsePort(s string) (port uint16, err error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return
	}
	port = uint16(n)
	return
}

func scanEd25519Cert(s *bufio.Scanner) (cert []byte, err error) {
	defer func() {
		if err == nil {
			err = s.Err()
		}
	}()
	if !s.Scan() {
		return
	}
	if s.Text() != "-----BEGIN ED25519 CERT-----" {
		err = fmt.Errorf(`[tordir.scanEd25519Cert] expects line "-----BEGIN ED25519 CERT-----": %w`, ErrInvalidFormat)
		return
	}
	buf := ""
	for {
		if !s.Scan() {
			return
		}
		if s.Text() == "-----END ED25519 CERT-----" {
			break
		}
		buf += s.Text()
	}
	if cert, err = base64.StdEncoding.DecodeString(buf); err != nil {
		err = fmt.Errorf(`[tordir.scanEd25519Cert] cannot decode cert payload as Base64": %s: %w`, err.Error(), ErrInvalidFormat)
		return
	}
	return
}
