package nfpm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/stretchr/testify/require"
)

func TestHardlinkYAMLConfiguration(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "payload"), []byte("data\n"), 0o755))

	config := strings.NewReader(`
name: hl
arch: amd64
platform: linux
version: 1.0.0
contents:
  - src: ` + root + `/payload
    dst: /opt/demo/payload
  - dst: /opt/demo/alias
    src: /opt/demo/payload
    type: hardlink
`)

	info, err := nfpm.Parse(config)
	require.NoError(t, err)
	require.Len(t, info.Contents, 2)
	require.Equal(t, files.TypeHardlink, info.Contents[1].Type)
	require.Equal(t, "/opt/demo/payload", info.Contents[1].Source)

	prepared, err := files.PrepareForPackager(info.Contents, 0o022, "deb", true, info.MTime)
	require.NoError(t, err)

	var link *files.Content
	for _, content := range prepared {
		if content.Destination == "/opt/demo/alias" {
			link = content
		}
	}
	require.NotNil(t, link)
	require.Equal(t, files.TypeHardlink, link.Type)
}
