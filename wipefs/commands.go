package wipefs

import (
	"fmt" // return errors
	"os"  // open device

	"github.com/isi-lincoln/goblkid"
	"github.com/isi-lincoln/goblkid/ext"
	"github.com/isi-lincoln/goblkid/fat"

	log "github.com/sirupsen/logrus"
)

// GetProbeInfo probes the passed in block and returns the probe info
func GetProbeInfo(blk string) (*goblkid.ProbeInfo, error) {
	fi, err := os.Open(blk)
	if err != nil {
		return nil, err
	}
	defer fi.Close()

	info := &goblkid.ProbeInfo{DeviceReader: fi}

	chain := &ext.Chain
	t, err := chain.Probe(info)

	log.Infof("returned: %t %v", t, err)

	return info, nil
}

// PrintProbeInfo prints the preliminary probe info
func PrintProbeInfo(info *goblkid.ProbeInfo) {
	log.Infof("%#v", info)
}

// WipeFileSystemSignature removes the magic string on the filesystem
func WipeFileSystemSignature(dev string) error {
	info, err := GetProbeInfo(dev)
	if err != nil {
		return err
	}

	switch info.ProbeName {
	case ext.Ext2Name:
		fallthrough
	case ext.Ext3Name:
		fallthrough
	case ext.Ext4Name:
		fallthrough
	case ext.Ext4devName:
		return wipeExt(dev)
	case fat.FatName:
		return fmt.Errorf("not implemented")
	default:
		return fmt.Errorf("unknown case: %s", info.ProbeName)
	}
}

func wipeExt(dev string) error {
	fi, err := os.OpenFile(dev, os.O_RDWR, 0777)
	if err != nil {
		return err
	}
	defer fi.Close()

	data := make([]byte, len(ext.ExtMagic[0].Magic))
	offset := int64(ext.ExtMagic[0].SuperblockKbOffset<<10 + ext.ExtMagic[0].MagicByteOffset) // nolint
	n, err := fi.WriteAt(data, offset)

	if err != nil {
		return err
	}

	if n != len(data) {
		return fmt.Errorf("write != length: %d != %d", n, len(data))
	}

	return nil
}
