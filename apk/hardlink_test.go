package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/stretchr/testify/require"
)

type apkEntry struct {
	header *tar.Header
	data   []byte
}

// apkStreams enumerates the concatenated gzip tar streams of an APK
// (control + data, plus signature when signed) as entry lists.
func apkStreams(t *testing.T, packageBytes []byte) [][]apkEntry {
	t.Helper()
	r := bytes.NewReader(packageBytes)
	gz, err := gzip.NewReader(r)
	require.NoError(t, err)

	var streams [][]apkEntry
	for {
		gz.Multistream(false)

		var entries []apkEntry
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			copy := *hdr
			entries = append(entries, apkEntry{header: &copy, data: data})
		}
		streams = append(streams, entries)

		// consume the remaining member bytes (e.g. tar padding) before
		// positioning on the next gzip member
		_, _ = io.Copy(io.Discard, gz)
		if err := gz.Reset(r); err != nil {
			require.ErrorIs(t, err, io.EOF)
			break
		}
	}
	return streams
}

func apkFindEntry(streams [][]apkEntry, name string) *apkEntry {
	for _, entries := range streams {
		for i := range entries {
			if entries[i].header.Name == name {
				return &entries[i]
			}
		}
	}
	return nil
}

func TestAPKHardlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "payload")
	require.NoError(t, os.WriteFile(source, []byte("same payload\n"), 0o755))

	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Version:     "1.0.0",
		Arch:        "amd64",
		Platform:    "linux",
		Maintainer:  "Harness <h@example.invalid>",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{Contents: files.Contents{
			{Source: source, Destination: "/opt/demo/payload", Type: files.TypeFile},
			{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
		}},
	}

	var packageBytes bytes.Buffer
	require.NoError(t, Default.Package(info, &packageBytes))
	streams := apkStreams(t, packageBytes.Bytes())

	link := apkFindEntry(streams, "opt/demo/alias")
	require.NotNil(t, link)
	require.Equal(t, byte(tar.TypeLink), link.header.Typeflag)
	require.Equal(t, "opt/demo/payload", link.header.Linkname)
	require.Zero(t, link.header.Size)
	require.Empty(t, link.data)
	// hard links carry no data of their own, so no apk content checksum exists
	require.NotContains(t, link.header.PAXRecords, "APK-TOOLS.checksum.SHA1")

	payload := apkFindEntry(streams, "opt/demo/payload")
	require.NotNil(t, payload)
	require.Equal(t, byte(tar.TypeReg), payload.header.Typeflag)
	require.Equal(t, "same payload\n", string(payload.data))

	// the data payload is only stored once, so installed size counts it once
	pkginfo := apkFindEntry(streams, ".PKGINFO")
	require.NotNil(t, pkginfo)
	for _, line := range strings.Split(string(pkginfo.data), "\n") {
		if value, ok := strings.CutPrefix(line, "size = "); ok {
			size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			require.NoError(t, err)
			require.Equal(t, int64(len("same payload\n")), size)
			return
		}
	}
	t.Fatal(".PKGINFO has no size field")
}

func TestAPKHardlinkError(t *testing.T) {
	info := &nfpm.Info{
		Name:        "hardlink-proof",
		Version:     "1.0.0",
		Arch:        "amd64",
		Platform:    "linux",
		Maintainer:  "Harness <h@example.invalid>",
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
