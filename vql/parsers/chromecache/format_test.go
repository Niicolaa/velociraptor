package chromecache

import (
	"encoding/binary"
	"testing"
)

func TestParseIndex(t *testing.T) {
	data := make([]byte, indexHeaderSize+4*4)
	binary.LittleEndian.PutUint32(data[0:], indexMagic)
	binary.LittleEndian.PutUint32(data[28:], 4) // table_len = 4

	// Two initialized addresses, two empty cells.
	binary.LittleEndian.PutUint32(data[indexHeaderSize+0:], 0xA0010000)
	binary.LittleEndian.PutUint32(data[indexHeaderSize+4:], 0)
	binary.LittleEndian.PutUint32(data[indexHeaderSize+8:], 0x80000001)
	binary.LittleEndian.PutUint32(data[indexHeaderSize+12:], 0)

	addrs, err := ParseIndex(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addrs got %d", len(addrs))
	}

	// Bad magic should error.
	bad := make([]byte, indexHeaderSize)
	if _, err := ParseIndex(bad); err == nil {
		t.Fatal("expected bad magic error")
	}
}

func TestParseEntry(t *testing.T) {
	data := make([]byte, entryStoreSize)
	binary.LittleEndian.PutUint32(data[0:], 0x12345678)         // hash
	binary.LittleEndian.PutUint32(data[4:], 0)                  // next
	binary.LittleEndian.PutUint64(data[24:], 13350000000000000) // creation_time
	binary.LittleEndian.PutUint32(data[32:], 11)               // key_len
	binary.LittleEndian.PutUint32(data[40:], 50)               // data_size[0]
	binary.LittleEndian.PutUint32(data[44:], 200)              // data_size[1]
	binary.LittleEndian.PutUint32(data[56:], 0xA0010001)       // data_addr[0]
	binary.LittleEndian.PutUint32(data[60:], 0x80000001)       // data_addr[1]
	copy(data[96:], "hello world\x00")

	e, err := ParseEntry(data)
	if err != nil {
		t.Fatal(err)
	}
	if e.Hash != 0x12345678 {
		t.Fatalf("hash %x", e.Hash)
	}
	if e.Key != "hello world" {
		t.Fatalf("key %q", e.Key)
	}
	if e.DataSize[1] != 200 {
		t.Fatalf("data size %d", e.DataSize[1])
	}
	if !e.DataAddr[1].IsExternal() {
		t.Fatal("expected external body addr")
	}
}

func TestChromiumTime(t *testing.T) {
	// 13350000000000000 us since 1601 -> sometime in 2024.
	ts := ChromiumTime(13350000000000000)
	if ts.Year() != 2024 {
		t.Fatalf("unexpected year %d (%v)", ts.Year(), ts)
	}
	if !ChromiumTime(0).IsZero() {
		t.Fatal("zero time expected for 0")
	}
}

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
