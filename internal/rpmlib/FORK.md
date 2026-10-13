# Vendored fork of go.digitalxero.dev/rpm

This directory is a verbatim copy of the production sources of
[`go.digitalxero.dev/rpm` v0.3.4](https://go.digitalxero.dev/rpm) (see
`LICENSE`), wired in through the `replace` directive in the repository root
`go.mod`. Test files of the upstream module are not copied.

## Local modification

The only functional change over v0.3.4 is payload hard link support, required
to back nFPM's `hardlink` content type:

- `FileBuilder.WithHardLink(target string)` declares an entry as an additional
  name for another in-package file.
- `(*rpmPackage).resolveHardlinks` validates the declarations (missing target,
  self reference, cycle, target that is a directory/symlink/ghost) and groups
  members by their terminal target.
- `processFiles` emits one shared `FILEDEVICES`/`FILEINODES` pair per group,
  records `FILELINKTOS` for the non-carrying members, stores payload, installed
  size and digest exactly once, and writes matching `nlink`/inode records to
  the newc cpio payload. The data-carrying member is the last one in path
  order, matching the layout rpmbuild produces (e.g. busybox) and what
  go-rpmutils/librpm expect.

When bumping the upstream dependency, port these changes onto the newer code
and drop the `replace` directive once upstream ships the feature.
