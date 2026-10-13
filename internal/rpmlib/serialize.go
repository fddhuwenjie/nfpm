package rpm

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
)

// serialize.go assembles the final RPM: it sorts files, builds the cpio payload,
// constructs the main header and signature indexes, and writes
// lead + signature + padding + header + payload.

// fileArrays holds the parallel per-file header arrays. Every slice must have the
// same length (the file count) or rpm rejects the package.
type fileArrays struct {
	dirnames    []string
	dirindexes  []int32
	basenames   []string
	sizes       []uint64
	modes       []uint16
	rdevs       []int16
	mtimes      []int32
	digests     []string
	linktos     []string
	flags       []int32
	usernames   []string
	groupnames  []string
	verifyflags []int32
	devices     []int32
	inodes      []int32
	langs       []string
	caps        []string
	colors      []int32
	classes     []string
	provides    [][]fileDep
	requires    [][]fileDep

	installedSize uint64
	anyCaps       bool
	anyColors     bool
	count         int
}

// renderFile is a single payload record to emit into the cpio archive. Content
// is either streamed (open != nil) or in-memory (body), never loaded whole for
// streamed sources.
type renderFile struct {
	index int // position in the file arrays (for back-filling the digest)
	// hardlinkMember marks a non-master entry of a hard link group: the cpio
	// header is emitted with size 0 and no data, and no per-file digest is
	// recorded in the header.
	hardlinkMember bool
	cpioName       string
	mode           uint32
	mtime          uint32
	ino            int
	nlink          int
	size           int64 // cpio content size (0 for dirs)
	open           func() (io.ReadCloser, error)
	body           []byte
	isRegular      bool
	hasPayload     bool
}

// hardlinkGroup is the set of package paths sharing one inode (and hence one
// payload). master carries the data, every other name is an additional link.
type hardlinkGroup struct {
	master  string
	members []string // sorted names, including master
}

// resolveHardlinks validates every hard link declaration and groups the entries
// by their terminal target. Chains (a link pointing at another link) are
// followed; missing targets, self references, cycles, and links to
// directories, symbolic links or ghost files are rejected.
func (p *rpmPackage) resolveHardlinks(names []string) (map[string]*hardlinkGroup, error) {
	groups := map[string]*hardlinkGroup{}
	memberOf := map[string]*hardlinkGroup{}

	for _, name := range names {
		fe := p.files[name]
		if fe.hardlinkTarget == "" {
			continue
		}

		seen := map[string]bool{name: true}
		chain := []string{name}
		cur := fe.hardlinkTarget
		for {
			target, ok := p.files[cur]
			if !ok {
				return nil, fmt.Errorf("rpm: hardlink %q: target %q is not packaged", name, cur)
			}
			if seen[cur] {
				return nil, fmt.Errorf("rpm: hardlink cycle detected: %s", strings.Join(append(chain, cur), " -> "))
			}
			seen[cur] = true
			chain = append(chain, cur)
			if target.hardlinkTarget == "" {
				switch {
				case target.isDirectory():
					return nil, fmt.Errorf("rpm: hardlink %q: target %q is a directory", name, cur)
				case target.symlink:
					return nil, fmt.Errorf("rpm: hardlink %q: target %q is a symbolic link", name, cur)
				case target.ftype&GhostFile != 0:
					return nil, fmt.Errorf("rpm: hardlink %q: target %q is a ghost file", name, cur)
				}
				break
			}
			cur = target.hardlinkTarget
		}

		group := groups[cur]
		if group == nil {
			group = &hardlinkGroup{master: cur}
			groups[cur] = group
			memberOf[cur] = group
		}
		group.members = append(group.members, name)
		memberOf[name] = group
	}

	for _, group := range groups {
		group.members = append(group.members, group.master)
		sort.Strings(group.members)
		// dedupe in case a name got registered twice through overlapping chains
		group.members = slices.Compact(group.members)
	}

	return memberOf, nil
}

func cpioName(p string) string {
	if len(p) > 0 && p[0] == '/' {
		return "." + p
	}
	return "./" + p
}

// processFiles walks the files in sorted path order and produces the header
// arrays plus the cpio render list.
func (p *rpmPackage) processFiles() (*fileArrays, []renderFile, error) {
	names := make([]string, 0, len(p.files))
	for name := range p.files {
		if name == "/" { // rpm forbids the root directory in the file list
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	memberOf, err := p.resolveHardlinks(names)
	if err != nil {
		return nil, nil, err
	}

	// Every hard link group shares one inode; inodes are assigned in path order
	// to payload-carrying entries (everyone except non-master links), and the
	// additional links reuse their master's inode.
	inoOf := make(map[string]int, len(names))
	nextIno := 1
	for _, name := range names {
		if group, ok := memberOf[name]; ok && name != group.master {
			continue
		}
		inoOf[name] = nextIno
		nextIno++
	}
	for name, group := range memberOf {
		inoOf[name] = inoOf[group.master]
	}

	fa := &fileArrays{}
	di := newDirIndex()
	rendersByIndex := make([]renderFile, len(names))

	for i, name := range names {
		fe := p.files[name]
		dir, base := path.Split(name)

		group := memberOf[name]
		// The data-carrying member of a hard link group is the last one in
		// path order: rpm sorts payload/header records by path, and both
		// rpmbuild and go-rpmutils expect every earlier member of an inode
		// group to be payload-less (this also covers the common busybox
		// layout, e.g. /bin/ash -> /bin/busybox).
		var carrier string
		isLinkMember := false
		if group != nil {
			carrier = group.members[len(group.members)-1]
			isLinkMember = name != carrier
		}

		perm := fe.mode & 0o7777
		var mode uint
		var size uint64    // installed size (header)
		var cpioSize int64 // payload content size
		linkto := ""
		nlink := 1
		hasPayload := fe.ftype&GhostFile == 0
		isRegular := false
		var body []byte
		var open func() (io.ReadCloser, error)

		switch {
		case fe.isDirectory():
			mode = perm | modeDir
			size = 4096
			nlink = 2
		case fe.symlink:
			mode = perm | modeSymlink
			body = []byte(fe.symlinkTarget)
			cpioSize = int64(len(body))
			size = uint64(cpioSize)
			linkto = fe.symlinkTarget
		default:
			mode = perm | modeRegular
			isRegular = true
			if isLinkMember {
				// Every non-carrying member ships without payload, installed
				// size or digest; FILELINKTOS names the carrying member.
				body, open, cpioSize = nil, nil, 0
				size = 0
				linkto = carrier
				nlink = len(group.members)
			} else {
				// The carrier uses the payload of the terminal target, even
				// when the carrier entry itself was registered as a link.
				contentFE := fe
				if fe.hardlinkTarget != "" {
					contentFE = p.files[group.master]
				}
				body = contentFE.body
				open = contentFE.open
				cpioSize = contentFE.contentSize()
				size = uint64(cpioSize)
				if group != nil {
					nlink = len(group.members)
				}
			}
		}
		// Digests are computed while streaming the payload; see streamPayload.
		digest := ""

		owner := fe.owner
		if owner == "" {
			owner = "root"
		}
		groupName := fe.group
		if groupName == "" {
			groupName = "root"
		}
		verify := int32(AllVerifyFlags)
		if fe.verifySet {
			verify = int32(fe.verifyFlags)
		}

		fa.dirindexes = append(fa.dirindexes, di.get(dir))
		fa.basenames = append(fa.basenames, base)
		fa.sizes = append(fa.sizes, size)
		fa.modes = append(fa.modes, uint16(mode))
		fa.rdevs = append(fa.rdevs, 1)
		fa.mtimes = append(fa.mtimes, int32(fe.mtime))
		fa.digests = append(fa.digests, digest)
		fa.linktos = append(fa.linktos, linkto)
		// Derive the spec flag from the authoritative specFile reference so a
		// later WithType cannot accidentally clear it.
		flags := int32(fe.ftype)
		if fe == p.specFile {
			flags |= fileFlagSpecFile
		}
		fa.flags = append(fa.flags, flags)
		fa.usernames = append(fa.usernames, owner)
		fa.groupnames = append(fa.groupnames, groupName)
		fa.verifyflags = append(fa.verifyflags, verify)
		fa.devices = append(fa.devices, 1)
		fa.inodes = append(fa.inodes, int32(inoOf[name]))
		fa.langs = append(fa.langs, fe.lang)
		fa.caps = append(fa.caps, fe.caps)
		fa.colors = append(fa.colors, int32(fe.color))
		fa.classes = append(fa.classes, fe.class)
		fa.provides = append(fa.provides, fe.provides)
		fa.requires = append(fa.requires, fe.requires)
		fa.installedSize += size
		if fe.caps != "" {
			fa.anyCaps = true
		}
		if fe.color != FileColorNone {
			fa.anyColors = true
		}

		rendersByIndex[i] = renderFile{
			index:          i,
			hardlinkMember: isLinkMember,
			cpioName:       cpioName(name),
			mode:           uint32(mode),
			mtime:          fe.mtime,
			ino:            inoOf[name],
			nlink:          nlink,
			size:           cpioSize,
			open:           open,
			body:           body,
			isRegular:      isRegular,
			hasPayload:     hasPayload,
		}
	}

	// The cpio payload is emitted in the path-sorted header order: librpm and
	// rpmutils correlate payload records with the header file arrays by index,
	// so the order must not be changed. cpio hard link records with a zero size
	// may validly precede their data-carrying master; extractors resolve them
	// through the shared inode.
	renders := rendersByIndex

	fa.dirnames = di.all()
	fa.count = len(names)
	return fa, renders, nil
}

// streamPayload writes the compressed cpio archive to spool, streaming each
// file's content (never loading it whole), and fills fa.digests for regular
// files as it goes. It returns the uncompressed archive size and the hex digest
// of the compressed payload.
func (p *rpmPackage) streamPayload(ctx context.Context, spool io.Writer, fa *fileArrays, renders []renderFile) (archiveSize uint64, payloadDigest string, err error) {
	payloadHash := p.payloadDigestAlgo.newHash()
	zw, err := p.compressor.newWriter(io.MultiWriter(spool, payloadHash))
	if err != nil {
		return 0, "", fmt.Errorf("rpm: creating %s writer: %w", p.compressor.name(), err)
	}
	cw := newCPIOWriter(zw)

	for _, rf := range renders {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		if !rf.hasPayload {
			continue
		}

		var content io.Reader
		var closer io.Closer
		switch {
		case rf.open != nil:
			rc, oerr := rf.open()
			if oerr != nil {
				return 0, "", fmt.Errorf("rpm: opening %q: %w", rf.cpioName, oerr)
			}
			content, closer = rc, rc
		default:
			content = bytes.NewReader(rf.body)
		}

		var fh hash.Hash
		if rf.isRegular && !rf.hardlinkMember {
			fh = p.fileDigestAlgo.newHash()
			content = io.TeeReader(content, fh)
		}

		werr := cw.writeEntry(rf.cpioName, rf.mode, rf.mtime, rf.ino, rf.nlink, rf.size, content)
		if closer != nil {
			closer.Close()
		}
		if werr != nil {
			return 0, "", werr
		}
		if rf.isRegular && !rf.hardlinkMember {
			fa.digests[rf.index] = hex.EncodeToString(fh.Sum(nil))
		}
	}

	if err := cw.close(); err != nil {
		return 0, "", err
	}
	if err := zw.Close(); err != nil {
		return 0, "", fmt.Errorf("rpm: closing %s writer: %w", p.compressor.name(), err)
	}
	return uint64(cw.written), hex.EncodeToString(payloadHash.Sum(nil)), nil
}

// writeTo streams the full RPM to w without holding the package in memory: the
// (compressed) payload is spooled to a temp file on disk, the small headers are
// built once the payload digests/sizes are known, and then lead + signature +
// header + spooled payload are streamed to w.
func (p *rpmPackage) writeTo(ctx context.Context, w io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	fa, renders, err := p.processFiles()
	if err != nil {
		return 0, err
	}

	spool, err := os.CreateTemp(p.tempDir, "rpm-payload-*")
	if err != nil {
		return 0, fmt.Errorf("rpm: creating payload spool: %w", err)
	}
	defer func() {
		spool.Close()
		os.Remove(spool.Name())
	}()

	archiveSize, payloadDigest, err := p.streamPayload(ctx, spool, fa, renders)
	if err != nil {
		return 0, err
	}
	info, err := spool.Stat()
	if err != nil {
		return 0, fmt.Errorf("rpm: stat payload spool: %w", err)
	}
	compressedSize := info.Size()

	// Merge any file-level dependencies into local copies of the provide/require
	// lists so the per-file dependency dictionary can index into them without
	// mutating the builder (keeping serialize pure/repeatable).
	mergedProvides := append([]*relation(nil), p.provides.rels...)
	mergedRequires := append([]*relation(nil), p.requires.rels...)
	ddict, fdx, fdn, anyFileDep := buildFileDeps(fa, &mergedProvides, &mergedRequires)
	classDict, fileClass, anyClass := buildClassDict(fa.classes)

	h := newIndex(regionImmutable)
	p.writeGenIndexes(h, fa, payloadDigest)
	if fa.count > 0 {
		p.writeFileIndexes(h, fa)
		if anyClass {
			h.add(tagClassDict, EntryStringSlice(classDict))
			h.add(tagFileClass, EntryInt32(fileClass))
		}
		if anyFileDep {
			h.add(tagDependsDict, EntryInt32(ddict))
			h.add(tagFileDependsX, EntryInt32(fdx))
			h.add(tagFileDependsN, EntryInt32(fdn))
		}
	}
	p.writeRelationIndexes(h, mergedProvides, mergedRequires, fa.count)
	p.writeScriptlets(h)
	p.writeTriggers(h)
	p.writeChangelog(h)
	if p.sourcePackage {
		p.writeSourceTags(h)
	}
	h.addEntries(p.customTags)
	headerBytes := h.bytes()

	s := newIndex(regionSignatures)
	if err := p.writeSignatures(s, headerBytes, spool, compressedSize, archiveSize); err != nil {
		return 0, err
	}
	s.addEntries(p.customSigs)
	sigBytes := s.bytes()

	// Stream lead + signature + padding + header to w, then copy the spooled
	// payload.
	cw := &countingWriter{w: w}
	cw.Write(writeLead(p.name, p.FullVersion(), p.sourcePackage))
	cw.Write(sigBytes)
	cw.Write(make([]byte, (8-len(sigBytes)%8)%8))
	cw.Write(headerBytes)
	if cw.err != nil {
		return cw.n, cw.err
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return cw.n, fmt.Errorf("rpm: rewinding payload spool: %w", err)
	}
	if _, err := io.Copy(cw, spool); err != nil { // cw.Write counts the bytes
		return cw.n, fmt.Errorf("rpm: writing payload: %w", err)
	}
	return cw.n, cw.err
}

// countingWriter tracks bytes written and the first error.
type countingWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.w.Write(b)
	c.n += int64(n)
	c.err = err
	return n, err
}

// buildClassDict builds the deduplicated CLASSDICT (index 0 is the empty class)
// and the per-file FILECLASS indexes.
func buildClassDict(classes []string) (dict []string, index []int32, any bool) {
	dict = []string{""}
	pos := map[string]int32{"": 0}
	index = make([]int32, len(classes))
	for i, c := range classes {
		if c == "" {
			continue
		}
		any = true
		j, ok := pos[c]
		if !ok {
			j = int32(len(dict))
			dict = append(dict, c)
			pos[c] = j
		}
		index[i] = j
	}
	return dict, index, any
}

// buildFileDeps builds the DEPENDSDICT plus per-file FILEDEPENDSX (offset) and
// FILEDEPENDSN (count). Each dictionary entry is (deptype<<24)|index, where
// deptype is 'P' for a provide or 'R' for a require and index points into the
// (merged) provide/require name array.
func buildFileDeps(fa *fileArrays, provides, requires *[]*relation) (ddict, fdx, fdn []int32, any bool) {
	fdx = make([]int32, fa.count)
	fdn = make([]int32, fa.count)
	for i := range fa.count {
		fdx[i] = int32(len(ddict))
		for _, d := range fa.provides[i] {
			ix := findOrAddRelation(provides, d)
			ddict = append(ddict, int32('P')<<24|(ix&0x00ffffff))
		}
		for _, d := range fa.requires[i] {
			ix := findOrAddRelation(requires, d)
			ddict = append(ddict, int32('R')<<24|(ix&0x00ffffff))
		}
		fdn[i] = int32(len(ddict)) - fdx[i]
		if fdn[i] > 0 {
			any = true
		}
	}
	return ddict, fdx, fdn, any
}

// findOrAddRelation returns the index of a matching relation in set, appending it
// if absent.
func findOrAddRelation(set *[]*relation, d fileDep) int32 {
	for i, r := range *set {
		if r.name == d.name && r.version == d.version && r.sense == d.sense {
			return int32(i)
		}
	}
	*set = append(*set, &relation{name: d.name, version: d.version, sense: d.sense})
	return int32(len(*set) - 1)
}
