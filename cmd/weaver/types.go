package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type functionTraceContext struct {
	binaryName   string
	FunctionName string
	Arguments    []argument
}

type argument struct {
	CType          string
	goType         goType
	StartingOffset int
	VariableName   string
	PrintfFormat   string
	TypeSize       int
	ArrayLength    int // Set as 0 if not array
}

type procInfo struct {
	Pid  uint32 `json:"pid,omitempty"`
	Ppid uint32 `json:"ppid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

// unmarshalBinary for procInfo
func (i *procInfo) unmarshalBinary(data []byte) error {

	data = bytes.Trim(data, "\x00")
	// proc info struct is 24 bytes long and should at least be 8 bytes long
	if len(data) > 24 || len(data) < 8 {
		return fmt.Errorf("error decoding process info")
	}
	i.Pid = binary.LittleEndian.Uint32(data[0:4])
	i.Ppid = binary.LittleEndian.Uint32(data[4:8])
	i.Comm = string(data[8:])

	return nil
}

func listAvailableTypes() {
	for _, t := range supportedTypes {
		fmt.Println(t)
	}
}
