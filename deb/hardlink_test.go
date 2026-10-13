package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/blakesmith/ar"
	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/stretchr/testify/require"
)

func hardlinkInfo(t *testing.T) *nfpm.Info {
	t.Helper()
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	require.NoError(t, os.WriteFile(payload, []byte("same payload\n"), 0o755))

	return &nfpm.Info{
		Name:        "hardlink-proof",
		Version:     "1.0.0",
		Arch:        "amd64",
		Platform:    "linux",
		Maintainer:  "Harness <harness@example.invalid>",
		Description: "hardlink contract",
		Overridables: nfpm.Overridables{Contents: files.Contents{
			{Source: payload, Destination: "/opt/demo/payload", Type: files.TypeFile},
			{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
			// an unrelated symlink must keep its own semantics
			{Source: "payload", Destination: "/opt/demo/shortcut", Type: files.TypeSymlink},
		}},
	}
}

func debDataTar(t *testing.T, packageBytes []byte) []*tar.Header {
	t.Helper()
	arReader := ar.NewReader(bytes.NewReader(packageBytes))
	for {
		member, err := arReader.Next()
		if errors.Is(err, io.EOF) {
			t.Fatal("data tarball not found")
		}
		require.NoError(t, err)
		if member.Name != "data.tar.gz" {
			continue
		}
		gz, err := gzip.NewReader(arReader)
		require.NoError(t, err)
		tr := tar.NewReader(gz)
		var headers []*tar.Header
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return headers
			}
			require.NoError(t, err)
			copy := *hdr
			headers = append(headers, &copy)
		}
	}
}

func findHeader(headers []*tar.Header, name string) *tar.Header {
	for _, h := range headers {
		if h.Name == name {
			return h
		}
	}
	return nil
}

func TestDebHardlink(t *testing.T) {
	var packageBytes bytes.Buffer
	require.NoError(t, (&Deb{}).Package(hardlinkInfo(t), &packageBytes))

	headers := debDataTar(t, packageBytes.Bytes())

	link := findHeader(headers, "opt/demo/alias")
	require.NotNil(t, link, "hardlink member missing")
	require.Equal(t, byte(tar.TypeLink), link.Typeflag)
	require.Equal(t, "opt/demo/payload", link.Linkname)
	require.Zero(t, link.Size, "hardlink member must not carry a second payload")

	payload := findHeader(headers, "./opt/demo/payload")
	require.NotNil(t, payload)
	require.Equal(t, byte(tar.TypeReg), payload.Typeflag)
	require.Equal(t, int64(len("same payload\n")), payload.Size)

	// parent directories are created for the link path
	require.NotNil(t, findHeader(headers, "./opt/demo/"))

	// the ordinary symlink is untouched by the new relation
	symlink := findHeader(headers, "./opt/demo/shortcut")
	require.NotNil(t, symlink)
	require.Equal(t, byte(tar.TypeSymlink), symlink.Typeflag)
	require.Equal(t, "payload", symlink.Linkname)

	// the payload member is emitted before the link, so sequential tar
	// extraction can resolve the hard link
	payloadIndex, linkIndex := -1, -1
	for i, h := range headers {
		switch h.Name {
		case "./opt/demo/payload":
			payloadIndex = i
		case "opt/demo/alias":
			linkIndex = i
		}
	}
	require.Less(t, payloadIndex, linkIndex)
}

func TestDebHardlinkErrorProducesNoPackage(t *testing.T) {
	info := hardlinkInfo(t)
	// point the link at a destination that is not packaged
	info.Contents = files.Contents{
		info.Contents[0],
		{Source: "/opt/demo/missing", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
	}

	var packageBytes bytes.Buffer
	err := (&Deb{}).Package(info, &packageBytes)
	require.Error(t, err)
	require.Empty(t, packageBytes.Bytes(), "a failed build must not leave a half package behind")
}
