package weaver

import (
	"debug/dwarf"
	"debug/elf"
	"io"
)

type TraceTarget struct {
	Name       string
	Parameters []Parameter
}

type Parameter struct {
	Name string
	Type string
}

// GetDwarfData returns the DWARF data from an ELF binary
func GetDwarfData(path string) (*dwarf.Data, error) {
	elfFile, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return nil, err
	}

	return dwarfData, nil
}

// ParseDwarfData takes DWARF data and returns a slice
// of TraceTargets for weaver to attach uprobes/ebpf to.
func ParseDwarfData(data *dwarf.Data) ([]TraceTarget, error) {

	linearReader := data.Reader()
	typeReader := data.Reader()

	var targets []TraceTarget

	var targetBeingRead *TraceTarget = nil

entryReadLoop:
	for {
		entry, err := linearReader.Next()
		if err == io.EOF {
			break entryReadLoop
		}
		if err != nil {
			return []TraceTarget{}, err
		}

		if targetBeingRead != nil {
			// currently reading in the parameters of a function symbol

			// Null entry is used to end function's list of parameters
			if entryIsNull(entry) {
				targets = append(targets, *targetBeingRead)
				targetBeingRead = nil
				continue entryReadLoop
			}

			// Get this parameter's name and type

			//...

			targetBeingRead.Parameters = append(targetBeingRead.Parameters, Parameter{})
		}

		// debug entry is a function/method symbol
		if entry.Tag == dwarf.TagSubprogram {

			targetBeingRead = &TraceTarget{}

			// collect the symbols name by finding it in the entry fields
			for i := range entry.Field {
				if entry.Field[i].Attr == dwarf.AttrName {
					targetBeingRead.Name = entry.Field[i].Val.(string)
				}
			}
		}

	}

	return targets, nil
}

func entryIsNull(e *dwarf.Entry) bool {
	return e.Children == false &&
		len(e.Field) == 0 &&
		e.Offset == 0 &&
		e.Tag == dwarf.Tag(0)
}
