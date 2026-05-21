package chromecache

import (
	"encoding/binary"
	"testing"
)

func TestCacheAddr(t *testing.T) {
	// External file address: initialized, type 0, file number 0x123.
	a := CacheAddr(0x80000000 | 0x123)
	if !a.IsExternal() {
		t.Fatal("expected external")
	}
	if a.FileNumber() != 0x123 {
		t.Fatalf("file number %x", a.FileNumber())
	}

	// Block file: initialized, type 3 (BLOCK_1K), 2 blocks, selector 1,
	// start block 5.
	b := CacheAddr(0x80000000 | (3 << 28) | (1 << 24) | (1 << 16) | 5)
	if !b.IsBlockFile() {
		t.Fatal("expected block file")
	}
	if b.BlockSize() != 1024 {
		t.Fatalf("block size %d", b.BlockSize())
	}
	if b.NumBlocks() != 2 {
		t.Fatalf("num blocks %d", b.NumBlocks())
	}
	if b.FileSelector() != 1 {
		t.Fatalf("selector %d", b.FileSelector())
	}
	if b.StartBlock() != 5 {
		t.Fatalf("start block %d", b.StartBlock())
	}
	if b.FileOffset() != blockHeaderSize+5*1024 {
		t.Fatalf("offset %d", b.FileOffset())
	}
}

func TestExtractHTTPResponse(t *testing.T) {
	// status line + two headers, NUL separated, double NUL terminated.
	raw := []byte("garbage\x00\x00HTTP/1.1 200 OK\x00Content-Type: text/html\x00Set-Cookie: a=1\x00Set-Cookie: b=2\x00\x00trailing")
	resp := ExtractHTTPResponse(raw)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.ResponseCode != 200 {
		t.Fatalf("code %d", resp.ResponseCode)
	}
	ct, _ := resp.Headers.Get("Content-Type")
	if ct != "text/html" {
		t.Fatalf("content type %v", ct)
	}
	cookies, _ := resp.Headers.Get("Set-Cookie")
	arr, ok := cookies.([]string)
	if !ok || len(arr) != 2 {
		t.Fatalf("cookies %v", cookies)
	}
}

func TestParseSimpleFile(t *testing.T) {
	key := "https://example.com/index.html"
	stream1 := []byte("<html>body</html>")
	stream0 := []byte("\x00\x00\x00HTTP/1.1 200 OK\x00Content-Type: text/html\x00\x00")

	buf := make([]byte, 0)
	header := make([]byte, simpleHeaderSize)
	binary.LittleEndian.PutUint64(header[0:], simpleInitialMagic)
	binary.LittleEndian.PutUint32(header[8:], 1)
	binary.LittleEndian.PutUint32(header[12:], uint32(len(key)))
	binary.LittleEndian.PutUint32(header[16:], 0xdeadbeef)
	buf = append(buf, header...)
	buf = append(buf, []byte(key)...)
	buf = append(buf, stream1...)

	eof1 := make([]byte, simpleEOFSize)
	binary.LittleEndian.PutUint64(eof1[0:], simpleFinalMagic)
	binary.LittleEndian.PutUint32(eof1[12:], uint32(len(stream1)))
	buf = append(buf, eof1...)

	buf = append(buf, stream0...)
	eof0 := make([]byte, simpleEOFSize)
	binary.LittleEndian.PutUint64(eof0[0:], simpleFinalMagic)
	binary.LittleEndian.PutUint32(eof0[12:], uint32(len(stream0)))
	buf = append(buf, eof0...)

	entry, err := ParseSimpleFile(buf)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Key != key {
		t.Fatalf("key %q", entry.Key)
	}
	if string(entry.Stream1) != string(stream1) {
		t.Fatalf("stream1 %q", entry.Stream1)
	}
	resp := ExtractHTTPResponse(entry.Stream0)
	if resp == nil || resp.ResponseCode != 200 {
		t.Fatalf("bad stream0 parse %+v", resp)
	}
}
