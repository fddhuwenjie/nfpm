package ipk

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
	"github.com/stretchr/testify/require"
)

func ipkDataEntries(t *testing.T, packageBytes []byte) []*tar.Header {
	t.Helper()
	outerGz, err := gzip.NewReader(bytes.NewReader(packageBytes))
	require.NoError(t, err)
	outer := tar.NewReader(outerGz)
	for {
		member, err := outer.Next()
		if errors.Is(err, io.EOF) {
			t.Fatal("data.tar.gz member missing")
		}
		require.NoError(t, err)
		if member.Name != "data.tar.gz" && member.Name != "./data.tar.gz" {
			continue
		}
		gz, err := gzip.NewReader(outer)
		require.NoError(t, err)
		inner := tar.NewReader(gz)
		var headers []*tar.Header
		for {
			hdr, err := inner.Next()
			if errors.Is(err, io.EOF) {
				return headers
			}
			require.NoError(t, err)
			copy := *hdr
			headers = append(headers, &copy)
		}
	}
}

func ipkFindHeader(headers []*tar.Header, name string) *tar.Header {
	for _, h := range headers {
		if h.Name == name {
			return h
		}
	}
	return nil
}

func TestIPKHardlink(t *testing.T) {
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
	headers := ipkDataEntries(t, packageBytes.Bytes())

	link := ipkFindHeader(headers, "./opt/demo/alias")
	require.NotNil(t, link)
	require.Equal(t, byte(tar.TypeLink), link.Typeflag)
	require.Equal(t, "opt/demo/payload", link.Linkname)
	require.Zero(t, link.Size)

	payload := ipkFindHeader(headers, "./opt/demo/payload")
	require.NotNil(t, payload)
	require.Equal(t, byte(tar.TypeReg), payload.Typeflag)
	require.Equal(t, int64(len("same payload\n")), payload.Size)

	// parent directories are still created for the link destination
	require.NotNil(t, ipkFindHeader(headers, "./opt/demo/"))
}

func TestIPKHardlinkError(t *testing.T) {
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
