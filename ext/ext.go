package ext

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/isi-lincoln/goblkid"
	"github.com/lunixbochs/struc"
)

// EXT constant values
const (
	EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER = 0x0001                               // nolint:golint,stylecheck
	EXT2_FEATURE_RO_COMPAT_LARGE_FILE   = 0x0002                               // nolint:golint,stylecheck
	EXT2_FEATURE_INCOMPAT_FILETYPE      = 0x0002                               // nolint:golint,stylecheck
	EXT2_FLAGS_TEST_FILESYS             = 0x0004                               // nolint:golint,stylecheck
	EXT2_FEATURE_RO_COMPAT_BTREE_DIR    = 0x0004                               // nolint:golint,stylecheck
	EXT2_FEATURE_INCOMPAT_META_BG       = 0x0010                               // nolint:golint,stylecheck
	EXT2_FEATURE_INCOMPAT_UNSUPPORTED   = ^uint32(EXT2_FEATURE_INCOMPAT_SUPP)  // nolint:golint,stylecheck
	EXT2_FEATURE_RO_COMPAT_UNSUPPORTED  = ^uint32(EXT2_FEATURE_RO_COMPAT_SUPP) // nolint:golint,stylecheck

	EXT3_FEATURE_INCOMPAT_UNSUPPORTED  = ^uint32(EXT3_FEATURE_INCOMPAT_SUPP)  // nolint:golint,stylecheck
	EXT3_FEATURE_INCOMPAT_RECOVER      = 0x0004                               // nolint:golint,stylecheck
	EXT3_FEATURE_COMPAT_HAS_JOURNAL    = 0x0004                               // nolint:golint,stylecheck
	EXT3_FEATURE_INCOMPAT_JOURNAL_DEV  = 0x0008                               // nolint:golint,stylecheck
	EXT3_FEATURE_RO_COMPAT_UNSUPPORTED = ^uint32(EXT3_FEATURE_RO_COMPAT_SUPP) // nolint:golint,stylecheck

	EXT4_FEATURE_RO_COMPAT_HUGE_FILE   = 0x0008                    // nolint:golint,stylecheck
	EXT4_FEATURE_RO_COMPAT_GDT_CSUM    = 0x0010                    // nolint:golint,stylecheck
	EXT4_FEATURE_RO_COMPAT_DIR_NLINK   = 0x0020                    // nolint:golint,stylecheck
	EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE = 0x0040                    // nolint:golint,stylecheck
	EXT4_FEATURE_INCOMPAT_EXTENTS      = 0x0040                    // nolint:golint,stylecheck
	EXT4_FEATURE_INCOMPAT_64BIT        = 0x0080                    // nolint:golint,stylecheck
	EXT4_FEATURE_INCOMPAT_MMP          = 0x0100                    // nolint:golint,stylecheck
	EXT4_FEATURE_INCOMPAT_FLEX_BG      = 0x0200                    // nolint:golint,stylecheck
	EXT4_SUPPORTS_EXT2                 = (2 << 16) + (6 << 8) + 29 // nolint:golint,stylecheck

	EXT2_FEATURE_RO_COMPAT_SUPP = ( // nolint:golint,stylecheck
	EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER |
		EXT2_FEATURE_RO_COMPAT_LARGE_FILE |
		EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
	EXT2_FEATURE_INCOMPAT_SUPP = ( // nolint:golint,stylecheck
	EXT2_FEATURE_INCOMPAT_FILETYPE |
		EXT2_FEATURE_INCOMPAT_META_BG)
	EXT3_FEATURE_RO_COMPAT_SUPP = ( // nolint:golint,stylecheck
	EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER |
		EXT2_FEATURE_RO_COMPAT_LARGE_FILE |
		EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
	EXT3_FEATURE_INCOMPAT_SUPP = ( // nolint:golint,stylecheck
	EXT2_FEATURE_INCOMPAT_FILETYPE |
		EXT3_FEATURE_INCOMPAT_RECOVER |
		EXT2_FEATURE_INCOMPAT_META_BG)
)

var (
	//extMagic is the magic number for ext filesystems
	extMagic = []goblkid.MagicInfo{ // nolint:gochecknoglobals
		{
			Magic:              "\123\357",  // nolint:gomnd
			SuperblockKbOffset: 0x400 >> 10, // nolint:gomnd
			MagicByteOffset:    0x38,        // nolint:gomnd
		},
	}
)

var Chain = goblkid.Chain{ // nolint:gochecknoglobals
	Jbd2Prober,
	Ext2Prober,
	Ext3Prober,
	Ext4Prober,
	Ext4DevProber,
}

func jbdProbe(info *goblkid.ProbeInfo, magic goblkid.MagicInfo) (bool, error) {
	sb, err := ext2GetSuper(info)
	if err != nil {
		return false, err
	}

	if (sb.FeatureIncompat & EXT3_FEATURE_INCOMPAT_JOURNAL_DEV) == 0 {
		return false, nil
	}

	extGetInfo(info, 2, sb)

	return true, nil
}

func ext2Probe(info *goblkid.ProbeInfo, magic goblkid.MagicInfo) (bool, error) {
	sb, err := ext2GetSuper(info)
	if err != nil {
		return false, err
	}
	/* do not parse ext3 */
	if sb.FeatureCompat&EXT3_FEATURE_COMPAT_HAS_JOURNAL != 0 ||
		/* features ext2 don't understand */
		sb.FeatureRoCompat&EXT2_FEATURE_RO_COMPAT_UNSUPPORTED != 0 ||
		sb.FeatureIncompat&EXT2_FEATURE_INCOMPAT_UNSUPPORTED != 0 {
		return false, nil
	}

	extGetInfo(info, 2, sb)

	return true, nil
}

func ext3Probe(info *goblkid.ProbeInfo, magic goblkid.MagicInfo) (bool, error) {
	sb, err := ext2GetSuper(info)
	if err != nil {
		return false, err
	}
	/* features ext3 don't understand */
	if sb.FeatureCompat&EXT3_FEATURE_COMPAT_HAS_JOURNAL == 0 {
		return false, nil
	}
	/* features ext3 don't understand */
	if sb.FeatureRoCompat&EXT3_FEATURE_RO_COMPAT_UNSUPPORTED != 0 ||
		sb.FeatureIncompat&EXT3_FEATURE_INCOMPAT_UNSUPPORTED != 0 {
		return false, nil
	}

	extGetInfo(info, 3, sb)

	return true, nil
}

func ext4Probe(info *goblkid.ProbeInfo, magic goblkid.MagicInfo) (bool, error) {
	sb, err := ext2GetSuper(info)
	if err != nil {
		return false, err
	}
	/* Distinguish from jbd */
	if sb.FeatureIncompat&EXT3_FEATURE_INCOMPAT_JOURNAL_DEV != 0 {
		return false, nil
	}
	/* features ext3 don't understand */
	if sb.FeatureRoCompat&EXT3_FEATURE_RO_COMPAT_UNSUPPORTED == 0 &&
		sb.FeatureIncompat&EXT3_FEATURE_INCOMPAT_UNSUPPORTED == 0 {
		return false, nil
	}
	/*
	 * If the filesystem is a OK for use by in-development
	 * filesystem code, and ext4dev is supported or ext4 is not
	 * supported, then don't call ourselves ext4, so we can redo
	 * the detection and mark the filesystem as ext4dev.
	 *
	 * If the filesystem is marked as in use by production
	 * filesystem, then it can only be used by ext4 and NOT by
	 * ext4dev.
	 */
	if sb.Flags&EXT2_FLAGS_TEST_FILESYS != 0 {
		return false, nil
	}

	extGetInfo(info, 4, sb)

	return true, nil
}

func ext4devProbe(info *goblkid.ProbeInfo, magic goblkid.MagicInfo) (bool, error) {
	sb, err := ext2GetSuper(info)
	if err != nil {
		return false, err
	}
	/* features ext3 don't understand */
	if sb.FeatureCompat&EXT3_FEATURE_COMPAT_HAS_JOURNAL == 0 {
		return false, nil
	}

	if sb.Flags&EXT2_FLAGS_TEST_FILESYS == 0 {
		return false, nil
	}

	extGetInfo(info, 4, sb)

	return true, nil
}

func ext2GetSuper(info *goblkid.ProbeInfo) (*ext2SuperBlock, error) {
	var sb ext2SuperBlock

	_, err := info.DeviceReader.Seek(
		int64(extMagic[0].SuperblockKbOffset<<10), // nolint:gomnd
		io.SeekStart,
	)

	if err != nil {
		return nil, err
	}

	err = struc.UnpackWithOrder(info.DeviceReader, &sb, binary.LittleEndian)

	return &sb, err
}

func extGetInfo(info *goblkid.ProbeInfo, extVersion int, sb *ext2SuperBlock) {
	info.Label = string(sb.VolumeName[:bytes.Index(sb.VolumeName[:], []byte{0})])
	info.UUID = string(sb.UUID[:])

	if sb.FeatureCompat&EXT3_FEATURE_COMPAT_HAS_JOURNAL != 0 {
		info.ExtJournal = string(sb.JournalUUID[:])
	}

	if extVersion != 2 && sb.FeatureCompat&EXT2_FEATURE_INCOMPAT_UNSUPPORTED != 0 {
		info.SecType = "ext2"
	}

	info.Version = fmt.Sprint(sb.RevLevel, ".", sb.MinorRevLevel)
}

var Jbd2Prober = goblkid.Prober{ // nolint:gochecknoglobals
	Name:       "jbd",
	Usage:      goblkid.FilesystemProbe,
	ProbeFunc:  jbdProbe,
	MagicInfos: extMagic,
}

var Ext2Prober = goblkid.Prober{ // nolint:gochecknoglobals
	Name:       "ext2",
	Usage:      goblkid.FilesystemProbe,
	ProbeFunc:  ext2Probe,
	MagicInfos: extMagic,
}

var Ext3Prober = goblkid.Prober{ // nolint:gochecknoglobals
	Name:       "ext3",
	Usage:      goblkid.FilesystemProbe,
	ProbeFunc:  ext3Probe,
	MagicInfos: extMagic,
}

var Ext4Prober = goblkid.Prober{ // nolint:gochecknoglobals
	Name:       "ext4",
	Usage:      goblkid.FilesystemProbe,
	ProbeFunc:  ext4Probe,
	MagicInfos: extMagic,
}

var Ext4DevProber = goblkid.Prober{ // nolint:gochecknoglobals
	Name:       "ext4dev",
	Usage:      goblkid.FilesystemProbe,
	ProbeFunc:  ext4devProbe,
	MagicInfos: extMagic,
}

type ext2SuperBlock struct {
	InodesCount          uint32
	BlocksCount          uint32
	RBlocksCount         uint32
	FreeBlocksCount      uint32
	FreeInodesCount      uint32
	FirstDataBlock       uint32
	LogBlockSize         uint32
	Dummy3               [7]uint32
	Magic                [2]uint8
	State                uint16
	Errors               uint16
	MinorRevLevel        uint16
	Lastcheck            uint32
	Checkinterval        uint32
	CreatorOs            uint32
	RevLevel             uint32
	DefResuid            uint16
	DefResgid            uint16
	FirstIno             uint32
	InodeSize            uint16
	BlockGroupNr         uint16
	FeatureCompat        uint32
	FeatureIncompat      uint32
	FeatureRoCompat      uint32
	UUID                 [16]uint8
	VolumeName           [16]uint8
	LastMounted          [64]int8
	AlgorithmUsageBitmap uint32
	PreallocBlocks       uint8
	PreallocDirBlocks    uint8
	ReservedGdtBlocks    uint16
	JournalUUID          [16]uint8
	JournalInum          uint32
	JournalDev           uint32
	LastOrphan           uint32
	HashSeed             [4]uint32
	DefHashVersion       uint8
	JnlBackupType        uint8
	ReservedWordPad      uint16
	DefaultMountOpts     uint32
	FirstMetaBg          uint32
	MkfsTime             uint32
	JnlBlocks            [17]uint32
	BlocksCountHi        uint32
	RBlocksCountHi       uint32
	FreeBlocksHi         uint32
	MinExtraIsize        uint16
	WantExtraIsize       uint16
	Flags                uint32
	RaidStride           uint16
	MmpInterval          uint16
	MmpBlock             uint64
	RaidStripeWidth      uint32
	Reserved             [163]uint32
}
