package files_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/goreleaser/nfpm/v2/files"
	"github.com/stretchr/testify/require"
)

const hardlinkPayload = "same payload\n"

func hardlinkSourceFile(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "payload")
	require.NoError(t, os.WriteFile(source, []byte(hardlinkPayload), 0o755))
	return source
}

func hardlinkContents(t *testing.T) files.Contents {
	t.Helper()
	return files.Contents{
		{Source: hardlinkSourceFile(t), Destination: "/opt/demo/payload", Type: files.TypeFile},
		{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
	}
}

func findPrepared(contents files.Contents, destination string) *files.Content {
	for _, content := range contents {
		if content.Destination == destination {
			return content
		}
	}
	return nil
}

func TestHardlinkPreparation(t *testing.T) {
	for _, packager := range []string{"", "deb", "rpm", "apk", "arch", "archlinux", "ipk", "msix"} {
		name := packager
		if name == "" {
			name = "all"
		}
		t.Run(name, func(t *testing.T) {
			got, err := files.PrepareForPackager(hardlinkContents(t), 0o022, packager, true, mtime)
			require.NoError(t, err)

			payload := findPrepared(got, "/opt/demo/payload")
			require.NotNil(t, payload)
			require.Equal(t, files.TypeFile, payload.Type)

			link := findPrepared(got, "/opt/demo/alias")
			require.NotNil(t, link, "hardlink entry must survive preparation")
			require.Equal(t, files.TypeHardlink, link.Type)
			require.Equal(t, "/opt/demo/payload", link.Source)
			require.Equal(t, "/opt/demo/alias", link.Destination)

			// the link participates in directory creation with its own path
			require.NotNil(t, findPrepared(got, "/opt/"))
			require.NotNil(t, findPrepared(got, "/opt/demo/"))

			// no explicit mode: the effective mode is inherited from the
			// payload target instead of shipping as zero
			require.Equal(t, payload.FileInfo.Mode, link.FileInfo.Mode)
			require.Equal(t, "root", link.FileInfo.Owner)
			require.Equal(t, "root", link.FileInfo.Group)
		})
	}
}

func TestHardlinkComesAfterItsPayload(t *testing.T) {
	// "/opt/demo/alias" sorts before "/opt/demo/payload": the topological
	// ordering must still place the payload first, so tar streams are valid.
	got, err := files.PrepareForPackager(hardlinkContents(t), 0o022, "deb", true, mtime)
	require.NoError(t, err)

	payloadIndex, linkIndex := -1, -1
	for i, content := range got {
		switch content.Destination {
		case "/opt/demo/payload":
			payloadIndex = i
		case "/opt/demo/alias":
			linkIndex = i
		}
	}
	require.GreaterOrEqual(t, payloadIndex, 0)
	require.Greater(t, linkIndex, payloadIndex)
}

func TestHardlinkChain(t *testing.T) {
	raw := files.Contents{
		{Source: hardlinkSourceFile(t), Destination: "/srv/app/payload", Type: files.TypeFile},
		{Source: "/srv/app/payload", Destination: "/srv/app/second", Type: files.TypeHardlink},
		{Source: "/srv/app/second", Destination: "/srv/app/third", Type: files.TypeHardlink},
	}
	got, err := files.PrepareForPackager(raw, 0o022, "deb", true, mtime)
	require.NoError(t, err)

	order := map[string]int{}
	for i, content := range got {
		order[content.Destination] = i
	}
	require.Less(t, order["/srv/app/payload"], order["/srv/app/second"])
	require.Less(t, order["/srv/app/second"], order["/srv/app/third"])
}

func TestHardlinkFailures(t *testing.T) {
	tests := []struct {
		name     string
		packager string
		raw      files.Contents
		expected error
	}{
		{
			name: "missing target",
			raw: files.Contents{
				{Source: "/opt/demo/missing", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkTargetMissing,
		},
		{
			name: "self reference",
			raw: files.Contents{
				{Source: "/opt/demo/self", Destination: "/opt/demo/self", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkSelf,
		},
		{
			name: "two node cycle",
			raw: files.Contents{
				{Source: "/opt/demo/b", Destination: "/opt/demo/a", Type: files.TypeHardlink},
				{Source: "/opt/demo/a", Destination: "/opt/demo/b", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkCycle,
		},
		{
			name: "three node cycle",
			raw: files.Contents{
				{Source: "/opt/demo/b", Destination: "/opt/demo/a", Type: files.TypeHardlink},
				{Source: "/opt/demo/c", Destination: "/opt/demo/b", Type: files.TypeHardlink},
				{Source: "/opt/demo/a", Destination: "/opt/demo/c", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkCycle,
		},
		{
			name: "target is a directory",
			raw: files.Contents{
				{Destination: "/opt/demo/dir", Type: files.TypeDir},
				{Source: "/opt/demo/dir", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkTargetType,
		},
		{
			name: "target is a symlink",
			raw: files.Contents{
				{Source: "/elsewhere", Destination: "/opt/demo/sym", Type: files.TypeSymlink},
				{Source: "/opt/demo/sym", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkTargetType,
		},
		{
			name:     "target is an rpm ghost",
			packager: "rpm",
			raw: files.Contents{
				{Source: "/var/lib/demo/gone", Destination: "/var/lib/demo/gone", Type: files.TypeRPMGhost},
				{Source: "/var/lib/demo/gone", Destination: "/var/lib/demo/alias", Type: files.TypeHardlink},
			},
			expected: files.ErrHardlinkTargetType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := files.PrepareForPackager(tt.raw, 0o022, tt.packager, true, mtime)
			require.Error(t, err)
			require.True(t, errors.Is(err, tt.expected), "want %v, got %v", tt.expected, err)
		})
	}
}

func TestHardlinkDestinationCollision(t *testing.T) {
	raw := files.Contents{
		{Source: hardlinkSourceFile(t), Destination: "/opt/demo/payload", Type: files.TypeFile},
		{Source: "/elsewhere", Destination: "/opt/demo/alias", Type: files.TypeSymlink},
		{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
	}
	_, err := files.PrepareForPackager(raw, 0o022, "deb", true, mtime)
	require.ErrorIs(t, err, files.ErrContentCollision)
}

func TestRegularFilesWithSameContentAreNotMerged(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	require.NoError(t, os.WriteFile(first, []byte("identical\n"), 0o644))
	require.NoError(t, os.WriteFile(second, []byte("identical\n"), 0o644))

	got, err := files.PrepareForPackager(files.Contents{
		{Source: first, Destination: "/opt/demo/a", Type: files.TypeFile},
		{Source: second, Destination: "/opt/demo/b", Type: files.TypeFile},
	}, 0o022, "deb", true, mtime)
	require.NoError(t, err)

	a := findPrepared(got, "/opt/demo/a")
	b := findPrepared(got, "/opt/demo/b")
	require.Equal(t, files.TypeFile, a.Type)
	require.Equal(t, files.TypeFile, b.Type)
	require.NotEqual(t, a.Source, b.Source)
}

func TestHardlinkTargetRemovedByPackagerFilter(t *testing.T) {
	raw := files.Contents{
		{Source: hardlinkSourceFile(t), Destination: "/opt/demo/payload", Type: files.TypeFile, Packager: "deb"},
		{Source: "/opt/demo/payload", Destination: "/opt/demo/alias", Type: files.TypeHardlink},
	}
	_, err := files.PrepareForPackager(raw, 0o022, "rpm", true, mtime)
	require.ErrorIs(t, err, files.ErrHardlinkTargetMissing)

	got, err := files.PrepareForPackager(raw, 0o022, "deb", true, mtime)
	require.NoError(t, err)
	require.NotNil(t, findPrepared(got, "/opt/demo/alias"))
}

func TestHardlinkConcurrentPreparation(t *testing.T) {
	scenarios := []files.Contents{
		{
			{Source: hardlinkSourceFile(t), Destination: "/opt/a/payload", Type: files.TypeFile},
			{Source: "/opt/a/payload", Destination: "/opt/a/alias", Type: files.TypeHardlink},
		},
		{
			{Source: hardlinkSourceFile(t), Destination: "/opt/b/payload", Type: files.TypeFile},
			{Source: "/opt/b/payload", Destination: "/opt/b/alias", Type: files.TypeHardlink},
		},
		{
			{Source: "/opt/missing", Destination: "/opt/c/alias", Type: files.TypeHardlink},
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 3*8)
	for range 8 {
		for i := range scenarios {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := files.PrepareForPackager(scenarios[i], 0o022, "deb", true, time.Unix(1700000000, 0))
				errs <- err
			}()
		}
	}
	wg.Wait()
	close(errs)

	var failures, successes int
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		failures++
		require.ErrorIs(t, err, files.ErrHardlinkTargetMissing)
	}
	require.Equal(t, 16, successes)
	require.Equal(t, 8, failures)
}
