package arch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

type archEntry struct {
	header *tar.Header
	data   []byte
}

func archEntries(t *testing.T, packageBytes []byte) []archEntry {
	t.Helper()
	decoder, err := zstd.NewReader(bytes.NewReader(packageBytes))
	require.NoError(t, err)
	defer decoder.Close()

	tr := tar.NewReader(decoder)
	var entries []archEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		copy := *hdr
		entries = append(entries, archEntry{header: &copy, data: data})
	}
	return entries
}

func archFindEntry(entries []archEntry, name string) *archEntry {
	for i := range entries {
		if entries[i].header.Name == name {
			return &entries[i]
		}
	}
	return nil
}

func TestArchHardlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "payload")
	require.NoError(t, os.WriteFile(source, []byte("same payload\n"), 0o755))

	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Version:     "1.0.0",
		Arch:        "amd64",
		Platform:    "linux",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{Contents: files.Contents{
			{Source: source, Destination: "/opt/demo/payload", Type: files.TypeFile},
			{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
		}},
	}

	var packageBytes bytes.Buffer
	require.NoError(t, Default.Package(info, &packageBytes))
	entries := archEntries(t, packageBytes.Bytes())

	link := archFindEntry(entries, "opt/demo/alias")
	require.NotNil(t, link)
	require.Equal(t, byte(tar.TypeLink), link.header.Typeflag)
	require.Equal(t, "opt/demo/payload", link.header.Linkname)
	require.Zero(t, link.header.Size)
	require.Empty(t, link.data)

	payload := archFindEntry(entries, "opt/demo/payload")
	require.NotNil(t, payload)
	require.Equal(t, byte(tar.TypeReg), payload.header.Typeflag)
	require.Equal(t, "same payload\n", string(payload.data))

	// the mtree describes the link as type=file with a link keyword and
	// without size/digests, while the payload keeps its regular record
	mtree := archFindEntry(entries, ".MTREE")
	require.NotNil(t, mtree)
	gz, err := gzip.NewReader(bytes.NewReader(mtree.data))
	require.NoError(t, err)
	mtreeBody, err := io.ReadAll(gz)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	var aliasLine, payloadLine string
	for _, line := range strings.Split(string(mtreeBody), "\n") {
		switch {
		case strings.HasPrefix(line, "./opt/demo/alias "):
			aliasLine = line
		case strings.HasPrefix(line, "./opt/demo/payload "):
			payloadLine = line
		}
	}
	require.Contains(t, aliasLine, "type=file")
	require.Contains(t, aliasLine, "link=./opt/demo/payload")
	require.NotContains(t, aliasLine, "md5digest")
	require.Contains(t, payloadLine, "md5digest")

	// package size counts the payload once
	pkginfo := archFindEntry(entries, ".PKGINFO")
	require.NotNil(t, pkginfo)
	require.Contains(t, string(pkginfo.data), "size = 13\n")
}

func TestArchHardlinkError(t *testing.T) {
	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Version:     "1.0.0",
		Arch:        "amd64",
		Platform:    "linux",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{Contents: files.Contents{
			{Source: "/opt/demo/missing", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
		}},
	}
	var packageBytes bytes.Buffer
	err := Default.Package(info, &packageBytes)
	require.Error(t, err)
	require.Empty(t, packageBytes.Bytes())
}
