/*
   Velociraptor - Dig Deeper
   Copyright (C) 2019-2025 Rapid7 Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package chromecache implements parsers for the Chromium disk cache
// formats. Chromium (and therefore every Electron application and the
// Chrome browser itself) stores cached HTTP responses using one of two
// on-disk formats:
//
//   - The "blockfile" cache: an "index" file plus "data_0".."data_3"
//     block files and "f_xxxxxx" external files for large payloads.
//
//   - The "simple" cache: one file per entry named "<hash>_0" (with an
//     "index-dir" containing a redundant index). This is the default on
//     most modern platforms.
//
// The functions here are pure parsers operating over byte slices so the
// IO (which goes through a Velociraptor accessor) can be handled by the
// caller.
package chromecache

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	// Magic numbers.
	indexMagic     uint32 = 0xC103CAC3
	blockFileMagic uint32 = 0xC104CAC3

	simpleInitialMagic uint64 = 0xfcfb6d1ba7725c30
	simpleFinalMagic   uint64 = 0xf4fa6f45970d41d8

	indexHeaderSize = 368
	blockHeaderSize = 8192

	// EntryStore is exactly one 256 byte block.
	entryStoreSize = 256

	simpleHeaderSize = 20
	simpleEOFSize    = 20

	// Default index hash table size when the header records 0.
	defaultTableLen = 0x10000
)

// EntryStoreSize returns the on-disk size of an EntryStore record.
func EntryStoreSize() int { return entryStoreSize }

// CacheAddr is the 32 bit address used throughout the blockfile cache.
type CacheAddr uint32

func (self CacheAddr) IsInitialized() bool { return self&0x80000000 != 0 }
func (self CacheAddr) FileType() int       { return int((self & 0x70000000) >> 28) }

// External files (f_xxxxxx).
func (self CacheAddr) FileNumber() int { return int(self & 0x0FFFFFFF) }

// Block files (data_N).
func (self CacheAddr) NumBlocks() int    { return int((self&0x03000000)>>24) + 1 }
func (self CacheAddr) FileSelector() int { return int((self & 0x00FF0000) >> 16) }
func (self CacheAddr) StartBlock() int   { return int(self & 0x0000FFFF) }

func (self CacheAddr) IsExternal() bool { return self.IsInitialized() && self.FileType() == 0 }
func (self CacheAddr) IsBlockFile() bool {
	return self.IsInitialized() && self.FileType() >= 1 && self.FileType() <= 4
}

func (self CacheAddr) BlockSize() int {
	switch self.FileType() {
	case 1: // RANKINGS
		return 36
	case 2: // BLOCK_256
		return 256
	case 3: // BLOCK_1K
		return 1024
	case 4: // BLOCK_4K
		return 4096
	}
	return 0
}

// FileOffset returns the byte offset of this address within its block
// file.
func (self CacheAddr) FileOffset() int {
	return blockHeaderSize + self.StartBlock()*self.BlockSize()
}

// EntryStore is the cache entry metadata record (one 256 byte block).
type EntryStore struct {
	Hash         uint32
	Next         CacheAddr
	RankingsNode CacheAddr
	ReuseCount   int32
	RefetchCount int32
	State        int32
	CreationTime uint64
	KeyLen       int32
	LongKey      CacheAddr
	DataSize     [4]int32
	DataAddr     [4]CacheAddr
	Flags        uint32
	SelfHash     uint32
	Key          string // in-place key when it fits
}

// ParseIndex parses the blockfile index file and returns the list of
// non-empty cache addresses found in the hash table.
func ParseIndex(data []byte) ([]CacheAddr, error) {
	if len(data) < indexHeaderSize {
		return nil, errors.New("chromecache: index file too short")
	}
	magic := binary.LittleEndian.Uint32(data[0:])
	if magic != indexMagic {
		return nil, fmt.Errorf("chromecache: bad index magic 0x%08x", magic)
	}

	tableLen := int(int32(binary.LittleEndian.Uint32(data[28:])))
	if tableLen <= 0 {
		tableLen = defaultTableLen
	}

	var result []CacheAddr
	off := indexHeaderSize
	for i := 0; i < tableLen; i++ {
		if off+4 > len(data) {
			break
		}
		addr := CacheAddr(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if addr.IsInitialized() {
			result = append(result, addr)
		}
	}
	return result, nil
}

// ParseEntry parses an EntryStore record from the given block. data must
// contain at least the 256 byte EntryStore at offset 0.
func ParseEntry(data []byte) (*EntryStore, error) {
	if len(data) < entryStoreSize {
		return nil, errors.New("chromecache: entry too short")
	}

	e := &EntryStore{
		Hash:         binary.LittleEndian.Uint32(data[0:]),
		Next:         CacheAddr(binary.LittleEndian.Uint32(data[4:])),
		RankingsNode: CacheAddr(binary.LittleEndian.Uint32(data[8:])),
		ReuseCount:   int32(binary.LittleEndian.Uint32(data[12:])),
		RefetchCount: int32(binary.LittleEndian.Uint32(data[16:])),
		State:        int32(binary.LittleEndian.Uint32(data[20:])),
		CreationTime: binary.LittleEndian.Uint64(data[24:]),
		KeyLen:       int32(binary.LittleEndian.Uint32(data[32:])),
		LongKey:      CacheAddr(binary.LittleEndian.Uint32(data[36:])),
		Flags:        binary.LittleEndian.Uint32(data[72:]),
		SelfHash:     binary.LittleEndian.Uint32(data[92:]),
	}
	for i := 0; i < 4; i++ {
		e.DataSize[i] = int32(binary.LittleEndian.Uint32(data[40+i*4:]))
		e.DataAddr[i] = CacheAddr(binary.LittleEndian.Uint32(data[56+i*4:]))
	}

	// When the key fits in the entry it is stored in-place starting at
	// offset 96, NUL terminated.
	if !e.LongKey.IsInitialized() {
		keyData := data[96:]
		if n := bytes.IndexByte(keyData, 0); n >= 0 {
			keyData = keyData[:n]
		}
		e.Key = string(keyData)
	}
	return e, nil
}

// ChromiumTime converts a base::Time internal value (microseconds since
// 1601-01-01 UTC) into a Go time.Time.
func ChromiumTime(microseconds uint64) time.Time {
	if microseconds == 0 {
		return time.Time{}
	}
	// Microseconds between 1601-01-01 and 1970-01-01.
	const epochDeltaMicros = 11644473600 * 1000000
	unixMicros := int64(microseconds) - epochDeltaMicros
	return time.UnixMicro(unixMicros).UTC()
}

// ParsedResponse holds the HTTP response metadata extracted from cache
// stream 0.
type ParsedResponse struct {
	StatusLine   string            `json:"StatusLine"`
	ResponseCode int64             `json:"ResponseCode"`
	Headers      *ordereddict.Dict `json:"Headers"`
}

// ExtractHTTPResponse extracts HTTP response headers from a cache
// stream-0 payload. The payload is a serialized HttpResponseInfo Pickle
// whose layout varies across Chromium versions, so rather than parsing
// every field we locate the embedded raw header block (NUL separated
// header lines, status line first, terminated by a double NUL) which is
// stable. Returns nil if no header block is found.
func ExtractHTTPResponse(stream0 []byte) *ParsedResponse {
	if len(stream0) == 0 {
		return nil
	}

	// The raw header block always starts with the HTTP status line.
	idx := bytes.Index(stream0, []byte("HTTP/"))
	if idx < 0 {
		return nil
	}

	block := stream0[idx:]
	// Header lines are separated by NUL bytes and the block is
	// terminated by an empty line (double NUL).
	if end := bytes.Index(block, []byte{0, 0}); end >= 0 {
		block = block[:end]
	}

	lines := bytes.Split(block, []byte{0})
	if len(lines) == 0 {
		return nil
	}

	result := &ParsedResponse{
		StatusLine: string(lines[0]),
		Headers:    ordereddict.NewDict(),
	}

	// Parse response code out of "HTTP/1.1 200 OK".
	parts := strings.SplitN(result.StatusLine, " ", 3)
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &result.ResponseCode)
	}

	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		kv := strings.SplitN(string(line), ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		// Headers may repeat (eg Set-Cookie). Preserve all of them.
		if existing, pres := result.Headers.Get(key); pres {
			switch t := existing.(type) {
			case []string:
				result.Headers.Set(key, append(t, value))
			case string:
				result.Headers.Set(key, []string{t, value})
			}
		} else {
			result.Headers.Set(key, value)
		}
	}
	return result
}

// Header returns the first value of the named response header (case
// insensitive), or "" if absent.
func (self *ParsedResponse) Header(name string) string {
	if self == nil || self.Headers == nil {
		return ""
	}
	for _, key := range self.Headers.Keys() {
		if strings.EqualFold(key, name) {
			value, _ := self.Headers.Get(key)
			switch t := value.(type) {
			case string:
				return t
			case []string:
				if len(t) > 0 {
					return t[0]
				}
			}
		}
	}
	return ""
}

// Decompress returns the body decompressed according to the HTTP
// Content-Encoding (gzip, deflate, br, zstd). Unknown or empty encodings
// return the data unchanged. On a decompression error the original data
// is returned along with the error so callers can fall back to the raw
// bytes.
func Decompress(encoding string, data []byte) ([]byte, error) {
	// Content-Encoding can in theory list several encodings; use the
	// last applied one (the others are uncommon in practice).
	enc := encoding
	if idx := strings.LastIndex(encoding, ","); idx >= 0 {
		enc = encoding[idx+1:]
	}

	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return data, nil

	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return data, err
		}
		defer r.Close()
		return readAllLimited(r, data)

	case "deflate":
		// "deflate" is ambiguous: some servers send zlib-wrapped data,
		// others send a raw deflate stream. Try zlib then raw flate.
		if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			defer r.Close()
			if out, err := readAllLimited(r, nil); err == nil {
				return out, nil
			}
		}
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		return readAllLimited(r, data)

	case "br":
		return readAllLimited(brotli.NewReader(bytes.NewReader(data)), data)

	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return data, err
		}
		defer r.Close()
		return readAllLimited(r, data)

	default:
		return data, nil
	}
}

// readAllLimited reads from r capping the output size. fallback is
// returned on error.
func readAllLimited(r io.Reader, fallback []byte) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize))
	if err != nil {
		return fallback, err
	}
	return out, nil
}

const maxDecompressedSize = 200 * 1024 * 1024

// commonMimeExtensions maps frequently seen MIME types to the file
// extension a human would expect (Go's mime package sometimes returns
// less friendly choices such as .htm or .jpe).
var commonMimeExtensions = map[string]string{
	"text/html":                ".html",
	"text/css":                 ".css",
	"text/plain":               ".txt",
	"text/javascript":          ".js",
	"application/javascript":   ".js",
	"application/x-javascript": ".js",
	"application/json":         ".json",
	"application/wasm":         ".wasm",
	"image/jpeg":               ".jpg",
	"image/png":                ".png",
	"image/gif":                ".gif",
	"image/webp":               ".webp",
	"image/svg+xml":            ".svg",
	"image/x-icon":             ".ico",
	"font/woff2":               ".woff2",
	"font/woff":                ".woff",
	"application/font-woff2":   ".woff2",
}

// SuggestFilename derives a sensible filename (with extension) for a
// cached resource. It prefers the basename from the URL when it already
// carries an extension, otherwise it appends an extension derived from
// the Content-Type header - mirroring the behaviour of the Python
// ccl_chromium_cache reference.
func SuggestFilename(rawurl, contentType string) string {
	name := ""
	if u, err := url.Parse(rawurl); err == nil {
		// A path ending in "/" refers to a directory index.
		if u.Path == "" || strings.HasSuffix(u.Path, "/") {
			name = "index"
		} else {
			name = path.Base(u.Path)
		}
	}
	if name == "" || name == "." || name == "/" {
		name = "index"
	}
	name = sanitizeFilename(name)

	if path.Ext(name) != "" {
		return name
	}

	return name + extensionForMIME(contentType)
}

func extensionForMIME(contentType string) string {
	if contentType == "" {
		return ""
	}
	mediaType := contentType
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		mediaType = contentType[:idx]
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	if ext, pres := commonMimeExtensions[mediaType]; pres {
		return ext
	}
	if exts, err := mime.ExtensionsByType(mediaType); err == nil && len(exts) > 0 {
		return exts[0]
	}
	return ""
}

func sanitizeFilename(name string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			return '_'
		}
		return r
	}, name)
}

// SimpleEntry holds the data extracted from a simple-cache "<hash>_0"
// file.
type SimpleEntry struct {
	Key       string
	Version   uint32
	KeyHash   uint32
	Stream0   []byte // HTTP response info (headers)
	Stream1   []byte // response body
}

// ParseSimpleFile parses a simple-cache entry file (the "<hash>_0"
// file). The layout is:
//
//	[SimpleFileHeader][key][stream1 data][EOF stream1][stream0 data][EOF stream0]
//
// Stream 0 carries the HTTP headers and stream 1 the response body.
func ParseSimpleFile(data []byte) (*SimpleEntry, error) {
	if len(data) < simpleHeaderSize+simpleEOFSize {
		return nil, errors.New("chromecache: simple file too short")
	}

	magic := binary.LittleEndian.Uint64(data[0:])
	if magic != simpleInitialMagic {
		return nil, fmt.Errorf("chromecache: bad simple magic 0x%016x", magic)
	}

	version := binary.LittleEndian.Uint32(data[8:])
	keyLength := int(binary.LittleEndian.Uint32(data[12:]))
	keyHash := binary.LittleEndian.Uint32(data[16:])

	if simpleHeaderSize+keyLength > len(data) {
		return nil, errors.New("chromecache: simple key length out of range")
	}

	entry := &SimpleEntry{
		Version: version,
		KeyHash: keyHash,
		Key:     string(data[simpleHeaderSize : simpleHeaderSize+keyLength]),
	}

	// The stream 0 EOF record is at the very end of the file.
	eof0Off := len(data) - simpleEOFSize
	if !validEOF(data[eof0Off:]) {
		// No trailing EOF - still return the key and header heuristics
		// over whatever follows the key.
		entry.Stream0 = data[simpleHeaderSize+keyLength:]
		return entry, nil
	}
	stream0Size := int(int32(binary.LittleEndian.Uint32(data[eof0Off+12:])))
	stream0Start := eof0Off - stream0Size
	if stream0Start < 0 || stream0Start > eof0Off {
		return entry, nil
	}
	entry.Stream0 = data[stream0Start:eof0Off]

	// The stream 1 EOF record precedes the stream 0 data.
	eof1Off := stream0Start - simpleEOFSize
	stream1Start := simpleHeaderSize + keyLength
	if eof1Off >= stream1Start && validEOF(data[eof1Off:]) {
		stream1Size := int(int32(binary.LittleEndian.Uint32(data[eof1Off+12:])))
		if stream1Size >= 0 && stream1Start+stream1Size <= eof1Off {
			entry.Stream1 = data[stream1Start : stream1Start+stream1Size]
		}
	}

	return entry, nil
}

func validEOF(data []byte) bool {
	if len(data) < simpleEOFSize {
		return false
	}
	return binary.LittleEndian.Uint64(data[0:]) == simpleFinalMagic
}
