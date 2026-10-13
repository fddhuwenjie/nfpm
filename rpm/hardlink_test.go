package rpm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/sassoftware/go-rpmutils"
	"github.com/sassoftware/go-rpmutils/cpio"
	"github.com/stretchr/testify/require"
)

const rpmHardlinkPayload = "same payload\n"

func rpmHardlinkSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "payload")
	require.NoError(t, os.WriteFile(source, []byte(rpmHardlinkPayload), 0o755))
	return source
}

func rpmBuild(t *testing.T, contents files.Contents) []byte {
	t.Helper()
	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Arch:        "amd64",
		Version:     "1.0.0",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{
			Contents: contents,
		},
	}
	var buf bytes.Buffer
	require.NoError(t, DefaultRPM.Package(info, &buf))
	return buf.Bytes()
}

func rpmFileByName(t *testing.T, list []rpmutils.FileInfo, name string) rpmutils.FileInfo {
	t.Helper()
	for _, f := range list {
		if f.Name() == name {
			return f
		}
	}
	require.Failf(t, "file not found", "no %s in rpm header", name)
	return nil
}

// iteratePayload returns the raw cpio payload entries in stream order together
// with the data each entry exposes (empty for payload-less links).
func iteratePayload(t *testing.T, packageBytes []byte) map[string]rpmPayloadEntry {
	t.Helper()
	rpmFile, err := rpmutils.ReadRpm(bytes.NewReader(packageBytes))
	require.NoError(t, err)
	pr, err := rpmFile.PayloadReader()
	require.NoError(t, err)

	out := map[string]rpmPayloadEntry{}
	for {
		hdr, err := pr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)

		data, err := io.ReadAll(pr)
		require.NoError(t, err)
		out[hdr.Filename()] = rpmPayloadEntry{
			size:  hdr.Filesize(),
			nlink: hdr.Nlink(),
			ino:   hdr.Ino(),
			data:  data,
		}
	}
	return out
}

type rpmPayloadEntry struct {
	size  int
	nlink int
	ino   int
	data  []byte
}

func TestRPMHardlink(t *testing.T) {
	// "alias" sorts before "payload", the classic busybox layout.
	packageBytes := rpmBuild(t, files.Contents{
		{Source: rpmHardlinkSource(t), Destination: "/opt/demo/payload", Type: files.TypeFile},
		{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
	})

	rpmFile, err := rpmutils.ReadRpm(bytes.NewReader(packageBytes))
	require.NoError(t, err)
	list, err := rpmFile.Header.GetFiles()
	require.NoError(t, err)

	payload := rpmFileByName(t, list, "/opt/demo/payload")
	alias := rpmFileByName(t, list, "/opt/demo/alias")

	// shared device/inode is what makes rpm install real hard links
	require.NotZero(t, payload.Inode())
	require.Equal(t, payload.Inode(), alias.Inode())
	require.Equal(t, payload.Device(), alias.Device())

	// the link ships no payload/digest and names the data-carrying member
	require.Zero(t, alias.Size())
	require.Empty(t, alias.Digest())
	require.Equal(t, "/opt/demo/payload", alias.Linkname())
	require.Equal(t, int64(len(rpmHardlinkPayload)), payload.Size())
	require.NotEmpty(t, payload.Digest())
	require.Empty(t, payload.Linkname())

	// cpio records carry the shared inode with nlink 2 and a zero size on link
	payloadHeader, err := extractFileHeaderFromRpm(packageBytes, "/opt/demo/payload")
	require.NoError(t, err)
	aliasHeader, err := extractFileHeaderFromRpm(packageBytes, "/opt/demo/alias")
	require.NoError(t, err)
	require.Equal(t, 2, payloadHeader.Nlink())
	require.Equal(t, 2, aliasHeader.Nlink())
	require.Equal(t, payloadHeader.Ino(), aliasHeader.Ino())
	require.NotZero(t, payloadHeader.Mode()&cpio.S_ISREG)
	require.NotZero(t, aliasHeader.Mode()&cpio.S_ISREG)
	require.Zero(t, aliasHeader.Filesize())
	require.Equal(t, len(rpmHardlinkPayload), payloadHeader.Filesize())

	// the payload can be streamed exactly once through the cpio reader
	entries := iteratePayload(t, packageBytes)
	require.Equal(t, len(rpmHardlinkPayload), entries["./opt/demo/payload"].size)
	require.Zero(t, entries["./opt/demo/alias"].size)
	require.Equal(t, 2, entries["./opt/demo/payload"].nlink)
	require.Equal(t, 2, entries["./opt/demo/alias"].nlink)
	require.Equal(t, entries["./opt/demo/payload"].ino, entries["./opt/demo/alias"].ino)
	require.Equal(t, rpmHardlinkPayload, string(entries["./opt/demo/payload"].data))
	require.Empty(t, entries["./opt/demo/alias"].data)
}

func TestRPMHardlinkWithLaterCarrier(t *testing.T) {
	// The link name sorts after the declared target: the package must still be
	// parseable, with exactly one copy of the data on the last group member.
	packageBytes := rpmBuild(t, files.Contents{
		{Source: rpmHardlinkSource(t), Destination: "/opt/demo/payload", Type: files.TypeFile},
		{Source: "/opt/demo/payload", Destination: "/opt/demo/zlink", Type: files.TypeHardlink},
	})

	rpmFile, err := rpmutils.ReadRpm(bytes.NewReader(packageBytes))
	require.NoError(t, err)
	list, err := rpmFile.Header.GetFiles()
	require.NoError(t, err)

	payload := rpmFileByName(t, list, "/opt/demo/payload")
	zlink := rpmFileByName(t, list, "/opt/demo/zlink")
	require.Equal(t, payload.Inode(), zlink.Inode())
	require.Zero(t, payload.Size())
	require.Equal(t, int64(len(rpmHardlinkPayload)), zlink.Size())
	require.Equal(t, "/opt/demo/zlink", payload.Linkname())

	entries := iteratePayload(t, packageBytes)
	require.Zero(t, entries["./opt/demo/payload"].size)
	require.Equal(t, len(rpmHardlinkPayload), entries["./opt/demo/zlink"].size)
	require.Equal(t, rpmHardlinkPayload, string(entries["./opt/demo/zlink"].data))
	require.Empty(t, entries["./opt/demo/payload"].data)
}
func TestRPMHardlinkChain(t *testing.T) {
	packageBytes := rpmBuild(t, files.Contents{
		{Source: rpmHardlinkSource(t), Destination: "/srv/app/payload", Type: files.TypeFile},
		{Source: "/srv/app/payload", Destination: "/srv/app/second", Type: files.TypeHardlink},
		{Source: "/srv/app/second", Destination: "/srv/app/third", Type: files.TypeHardlink},
	})

	rpmFile, err := rpmutils.ReadRpm(bytes.NewReader(packageBytes))
	require.NoError(t, err)
	list, err := rpmFile.Header.GetFiles()
	require.NoError(t, err)

	inode := rpmFileByName(t, list, "/srv/app/payload").Inode()
	for _, name := range []string{"/srv/app/second", "/srv/app/third"} {
		require.Equal(t, inode, rpmFileByName(t, list, name).Inode(), name)
	}

	entries := iteratePayload(t, packageBytes)
	payloadCopies := 0
	for _, entry := range entries {
		if string(entry.data) == rpmHardlinkPayload {
			payloadCopies++
		}
	}
	require.Equal(t, 1, payloadCopies, "payload must be stored exactly once")
	require.Equal(t, rpmHardlinkPayload, string(entries["./srv/app/third"].data))
	require.Empty(t, entries["./srv/app/payload"].data)
	require.Empty(t, entries["./srv/app/second"].data)
}

func TestRPMHardlinkError(t *testing.T) {
	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Arch:        "amd64",
		Version:     "1.0.0",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{Contents: files.Contents{
			{Source: "/opt/demo/missing", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
		}},
	}
	var buf bytes.Buffer
	err := DefaultRPM.Package(info, &buf)
	require.Error(t, err)
	require.Empty(t, buf.Bytes())
}

func TestSRPMHardlink(t *testing.T) {
	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Arch:        "amd64",
		Version:     "1.0.0",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{Contents: files.Contents{
			{Source: rpmHardlinkSource(t), Destination: "/opt/demo/payload", Type: files.TypeFile},
			{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
		}},
	}

	var buf bytes.Buffer
	require.NoError(t, DefaultSRPM.Package(info, &buf))

	// the bundled source tarball contains the hard link as a tar link entry
	sourceName := "hardlink-proof-1.0.0.tar.gz"
	archive, err := extractFileFromRpm(buf.Bytes(), "/"+sourceName)
	require.NoError(t, err)

	gz, err := gzip.NewReader(bytes.NewReader(archive))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var link *tar.Header
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "opt/demo/alias" {
			copy := *hdr
			link = &copy
		}
	}
	require.NotNil(t, link)
	require.Equal(t, byte(tar.TypeLink), link.Typeflag)
	require.Equal(t, "opt/demo/payload", link.Linkname)
}
