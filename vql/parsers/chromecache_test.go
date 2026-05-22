package parsers_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"log"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"www.velocidex.com/golang/velociraptor/accessors"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/acl_managers"
	"www.velocidex.com/golang/velociraptor/vql/parsers"
	vfilter "www.velocidex.com/golang/vfilter"

	_ "www.velocidex.com/golang/velociraptor/accessors/file"
)

const (
	cacheInitMagic  uint64 = 0xfcfb6d1ba7725c30
	cacheFinalMagic uint64 = 0xf4fa6f45970d41d8
	cacheIndexMagic uint32 = 0xC103CAC3
)

// writeSimpleCacheEntry builds a Chromium "simple cache" entry file.
func writeSimpleCacheEntry(t *testing.T, dir, name, key string, stream0, stream1 []byte) {
	buf := make([]byte, 20)
	binary.LittleEndian.PutUint64(buf[0:], cacheInitMagic)
	binary.LittleEndian.PutUint32(buf[8:], 1)
	binary.LittleEndian.PutUint32(buf[12:], uint32(len(key)))
	binary.LittleEndian.PutUint32(buf[16:], 0xdeadbeef)
	buf = append(buf, []byte(key)...)
	buf = append(buf, stream1...)

	eof1 := make([]byte, 20)
	binary.LittleEndian.PutUint64(eof1[0:], cacheFinalMagic)
	binary.LittleEndian.PutUint32(eof1[12:], uint32(len(stream1)))
	buf = append(buf, eof1...)

	buf = append(buf, stream0...)
	eof0 := make([]byte, 20)
	binary.LittleEndian.PutUint64(eof0[0:], cacheFinalMagic)
	binary.LittleEndian.PutUint32(eof0[12:], uint32(len(stream0)))
	buf = append(buf, eof0...)

	require.NoError(t, os.WriteFile(filepath.Join(dir, name), buf, 0644))
}

// writeBlockFileCache builds a minimal but real Chromium "blockfile"
// disk cache: an index file, a BLOCK_256 data file (data_1) holding the
// EntryStore and the stream-0 headers, and an external f_000001 file
// holding the stream-1 body.
func writeBlockFileCache(t *testing.T, dir, key string, stream0, body []byte) {
	const blockHeaderSize = 8192
	const entryBlock = 0
	const headerBlock = 1

	// data_1 is a BLOCK_256 file. Reserve header + a few blocks.
	data1 := make([]byte, blockHeaderSize+4*256)
	binary.LittleEndian.PutUint32(data1[0:], 0xC104CAC3) // block magic

	// Addresses (see CacheAddr bitfield):
	//   type 2 = BLOCK_256, selector 1 (data_1).
	entryAddr := uint32(0x80000000 | (2 << 28) | (1 << 16) | entryBlock)
	headerAddr := uint32(0x80000000 | (2 << 28) | (1 << 16) | headerBlock)
	bodyAddr := uint32(0x80000000 | 1) // external, f_000001

	// EntryStore at block 0.
	entry := make([]byte, 256)
	binary.LittleEndian.PutUint32(entry[0:], 0xCAFEBABE) // hash
	binary.LittleEndian.PutUint64(entry[24:], 13350000000000000)
	binary.LittleEndian.PutUint32(entry[32:], uint32(len(key)))
	binary.LittleEndian.PutUint32(entry[40:], uint32(len(stream0))) // data_size[0]
	binary.LittleEndian.PutUint32(entry[44:], uint32(len(body)))    // data_size[1]
	binary.LittleEndian.PutUint32(entry[56:], headerAddr)           // data_addr[0]
	binary.LittleEndian.PutUint32(entry[60:], bodyAddr)             // data_addr[1]
	copy(entry[96:], key)
	copy(data1[blockHeaderSize+entryBlock*256:], entry)

	// Stream 0 (HTTP headers) at block 1.
	copy(data1[blockHeaderSize+headerBlock*256:], stream0)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "data_1"), data1, 0644))

	// External body file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f_000001"), body, 0644))

	// Index file: header + a single bucket pointing at the entry.
	index := make([]byte, 368+4)
	binary.LittleEndian.PutUint32(index[0:], cacheIndexMagic)
	binary.LittleEndian.PutUint32(index[28:], 1) // table_len = 1
	binary.LittleEndian.PutUint32(index[368:], entryAddr)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index"), index, 0644))
}

func runChromeCache(t *testing.T, path string) []*ordereddict.Dict {
	scope := vql_subsystem.MakeScope()
	scope.SetLogger(log.New(os.Stderr, "", 0))
	scope.AppendVars(ordereddict.NewDict().
		Set(vql_subsystem.ACL_MANAGER_VAR, acl_managers.NullACLManager{}))
	defer scope.Close()

	ospath, err := accessors.NewGenericOSPath(path)
	require.NoError(t, err)

	ctx := context.Background()
	plugin := parsers.ChromeCachePlugin{}
	args := ordereddict.NewDict().
		Set("path", ospath).
		Set("accessor", "file").
		Set("include_content", true)

	var rows []*ordereddict.Dict
	for row := range plugin.Call(ctx, scope, args) {
		rows = append(rows, row.(*ordereddict.Dict))
	}
	return rows
}

func getStr(row *ordereddict.Dict, key string) string {
	v, _ := row.Get(key)
	s, _ := v.(string)
	return s
}

func TestChromeCacheSimple(t *testing.T) {
	dir := t.TempDir()
	stream0 := []byte("\x00\x00HTTP/1.1 200 OK\x00Content-Type: text/html\x00\x00")
	writeSimpleCacheEntry(t, dir, "0123456789abcdef_0",
		"https://example.com/a.html",
		stream0, []byte("BODY-A"))
	writeSimpleCacheEntry(t, dir, "fedcba9876543210_0",
		"https://example.com/b.js",
		[]byte("\x00HTTP/1.1 404 Not Found\x00\x00"), []byte("BODY-B-LONGER"))

	rows := runChromeCache(t, dir)
	require.Len(t, rows, 2)

	sort.Slice(rows, func(i, j int) bool {
		return getStr(rows[i], "URL") < getStr(rows[j], "URL")
	})

	assert.Equal(t, "https://example.com/a.html", getStr(rows[0], "URL"))
	code, _ := rows[0].Get("StatusCode")
	assert.Equal(t, int64(200), code)
	content, _ := rows[0].Get("Content")
	assert.Equal(t, "BODY-A", string(content.([]byte)))

	assert.Equal(t, "https://example.com/b.js", getStr(rows[1], "URL"))
	code, _ = rows[1].Get("StatusCode")
	assert.Equal(t, int64(404), code)
}

func TestChromeCacheDecompressAndFilename(t *testing.T) {
	dir := t.TempDir()

	plain := []byte("console.log('hello from cache');")
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(plain)
	_ = gw.Close()

	stream0 := []byte("\x00HTTP/1.1 200 OK\x00Content-Type: application/javascript\x00Content-Encoding: gzip\x00\x00")
	writeSimpleCacheEntry(t, dir, "aaaabbbbccccdddd_0",
		"https://cdn.example.com/static/app.js?v=9", stream0, gz.Bytes())

	rows := runChromeCache(t, dir)
	require.Len(t, rows, 1)
	row := rows[0]

	// The uploaded Content should be the DECOMPRESSED body, just like
	// the Python reference produces.
	content, _ := row.Get("Content")
	assert.Equal(t, string(plain), string(content.([]byte)))

	// And the suggested filename should carry the real extension.
	assert.Equal(t, "app.js", getStr(row, "Filename"))
	assert.Equal(t, "application/javascript", getStr(row, "ContentType"))
}

func TestChromeCacheBlockFile(t *testing.T) {
	dir := t.TempDir()
	stream0 := []byte("\x00\x00HTTP/1.1 200 OK\x00Content-Type: application/json\x00\x00")
	body := []byte(`{"hello":"world"}`)
	writeBlockFileCache(t, dir, "https://api.example.com/data.json", stream0, body)

	rows := runChromeCache(t, dir)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "https://api.example.com/data.json", getStr(row, "URL"))
	assert.Equal(t, "cafebabe", getStr(row, "EntryID"))

	code, _ := row.Get("StatusCode")
	assert.Equal(t, int64(200), code)

	headers, _ := row.Get("Headers")
	ct, _ := headers.(*ordereddict.Dict).Get("Content-Type")
	assert.Equal(t, "application/json", ct)

	// The body was stored in an external f_ file - confirm it is read
	// back correctly through the block-file address indirection.
	content, _ := row.Get("Content")
	assert.Equal(t, `{"hello":"world"}`, string(content.([]byte)))
}

var _ vfilter.Row = &ordereddict.Dict{}
