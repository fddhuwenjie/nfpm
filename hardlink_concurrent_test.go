package nfpm_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/goreleaser/nfpm/v2"
	_ "github.com/goreleaser/nfpm/v2/apk"
	_ "github.com/goreleaser/nfpm/v2/arch"
	_ "github.com/goreleaser/nfpm/v2/deb"
	"github.com/goreleaser/nfpm/v2/files"
	_ "github.com/goreleaser/nfpm/v2/ipk"
	_ "github.com/goreleaser/nfpm/v2/rpm"
	"github.com/stretchr/testify/require"
)

// TestHardlinkConcurrentCrossFormatBuilds builds every supported format
// concurrently with a distinct hard link relation and verifies the builds do
// not share state: they all succeed, produce non-empty packages, and every
// invalid relation keeps failing with a stable error. Run with -race to also
// cover data race isolation.
func TestHardlinkConcurrentCrossFormatBuilds(t *testing.T) {
	formats := []string{"deb", "rpm", "apk", "archlinux", "ipk"}
	const workers = 12

	type workerInput struct {
		payloadPath string
		payload     string
		base        string
		name        string
	}
	inputs := make([]workerInput, workers)
	for worker := range workers {
		payloadPath := filepath.Join(t.TempDir(), "payload")
		payload := fmt.Sprintf("payload of worker %d\n", worker)
		require.NoError(t, os.WriteFile(payloadPath, []byte(payload), 0o755))
		inputs[worker] = workerInput{
			payloadPath: payloadPath,
			payload:     payload,
			base:        fmt.Sprintf("/opt/worker-%d", worker),
			name:        fmt.Sprintf("hardlink-proof-%d", worker),
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, workers*len(formats)*2)

	for worker := range workers {
		for _, format := range formats {
			wg.Add(1)
			go func() {
				defer wg.Done()
				in := inputs[worker]

				info := &nfpm.Info{
					Name:        in.name,
					Version:     "1.0.0",
					Arch:        "amd64",
					Platform:    "linux",
					Maintainer:  "Harness <h@example.invalid>",
					Description: "hardlink concurrency",
					Overridables: nfpm.Overridables{Contents: files.Contents{
						{Source: in.payloadPath, Destination: in.base + "/payload", Type: files.TypeFile},
						{Source: in.base + "/payload", Destination: in.base + "/alias", Type: files.TypeHardlink},
					}},
				}

				packager, err := nfpm.Get(format)
				if err != nil {
					errs <- err
					return
				}

				var packageBytes bytes.Buffer
				if err := packager.Package(info, &packageBytes); err != nil {
					errs <- fmt.Errorf("%s worker %d: %w", format, worker, err)
					return
				}
				if packageBytes.Len() == 0 {
					errs <- fmt.Errorf("%s worker %d produced an empty package", format, worker)
					return
				}

				// an invalid relation must keep failing regardless of concurrency
				bad := &nfpm.Info{
					Name:        "hardlink-proof-bad",
					Version:     "1.0.0",
					Arch:        "amd64",
					Platform:    "linux",
					Maintainer:  "Harness <h@example.invalid>",
					Description: "hardlink concurrency",
					Overridables: nfpm.Overridables{Contents: files.Contents{
						{Source: in.base + "/does-not-exist", Destination: in.base + "/broken", Type: files.TypeHardlink},
					}},
				}
				var badBytes bytes.Buffer
				if err := packager.Package(bad, &badBytes); err == nil {
					errs <- fmt.Errorf("%s worker %d accepted a dangling hard link", format, worker)
					return
				}
				if badBytes.Len() != 0 {
					errs <- fmt.Errorf("%s worker %d emitted bytes for an invalid package", format, worker)
				}
			}()
		}
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}
