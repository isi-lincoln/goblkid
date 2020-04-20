package goblkid

import (
	"io"
)

// ProbeUsage is the type of probe being used
type ProbeUsage int

// ProbeUsage mappings
const (
	FilesystemProbe ProbeUsage = 1 << iota
	RaidProbe
	CryptoProbe
	OtherProbe
)

type Prober struct {
	Name       string
	Usage      ProbeUsage
	ProbeFunc  func(info *ProbeInfo, magicInfo MagicInfo) (bool, error)
	MagicInfos []MagicInfo
}

func (pr *Prober) Probe(info *ProbeInfo) (bool, error) {
	for _, magic := range pr.MagicInfos {
		ok, err := pr.ProbeFunc(info, magic)
		if err != nil {
			return false, err
		}

		if ok {
			return true, nil
		}
	}

	return false, nil
}

type MagicInfo struct {
	Magic              string
	SuperblockKbOffset uint64
	MagicByteOffset    uint64
}

type ProbeInfo struct {
	DeviceReader io.ReadSeeker
	Offset       int64
	Size         int64

	Devno     int
	DiskDevno int
	BlockSize uint64 /* from BLKSSZGET ioctl */
	Mode      int    /* from stat.sb_mode */

	ProbeName string

	UUID  string
	Label string

	ExtJournal string
	SecType    string

	Version string
}

type Chain []Prober

func (chain Chain) Probe(info *ProbeInfo) (bool, error) {
	for _, prober := range chain {
		ok, err := prober.Probe(info)
		if err != nil {
			return false, err
		}

		if ok {
			info.ProbeName = prober.Name
			return true, nil
		}
	}

	return false, nil
}
