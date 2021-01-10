package mrt

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"time"
)

type DataType uint16
type DataSubType uint16


const (
	TABLE_DUMP_V2 DataType = 13
)

type header struct {
	Timestamp  uint32
	Type       DataType
	Subtype    DataSubType
	DataLength uint32
}

type Record struct {
	Timestamp time.Time
	Type      DataType
	SubType   DataSubType
	Data      interface{}
}

type Parser struct {
	File    *os.File
	Records []Record
}

func (p *Parser) Parse() {
	p.Records = make([]Record, 0, 32)
	for {
		var record Record
		header := new(header)
		err := p.parseInto(header)
		if err == io.EOF {
			break
		}

		buffer := bytes.NewBuffer(make([]byte, 0, header.DataLength))
		_, err = io.CopyN(buffer, p.File, int64(header.DataLength))
		if err == io.EOF {
			break
		}

		var data interface{}

		switch header.Type {
		case TABLE_DUMP_V2:
			data = ParseTableDumpV2(buffer, header.Subtype)
			break
		}

		record = Record{
			Timestamp: time.Unix(int64(header.Timestamp), 0),
			Type:      header.Type,
			SubType:   header.Subtype,
			Data:      data,
		}

		p.Records = append(p.Records, record)
	}
	return
}

func (p *Parser) parseInto(format interface{}) error {
	return binary.Read(p.File, binary.BigEndian, format)
}
