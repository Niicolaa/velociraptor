package v8

import (
	"reflect"
	"testing"

	"github.com/Velocidex/ordereddict"
)

// enc is a small helper to build byte-accurate V8 serialized blobs for
// tests. The byte layout it produces matches V8's value-serializer.cc
// (cross checked against the ccl_chromium_reader reference
// implementation).
type enc struct{ buf []byte }

func (self *enc) tag(t byte) *enc { self.buf = append(self.buf, t); return self }
func (self *enc) raw(b ...byte) *enc { self.buf = append(self.buf, b...); return self }

func (self *enc) varint(v uint64) *enc {
	for v >= 0x80 {
		self.buf = append(self.buf, byte(v)|0x80)
		v >>= 7
	}
	self.buf = append(self.buf, byte(v))
	return self
}

func (self *enc) zigzag(v int64) *enc {
	return self.varint(uint64((v << 1) ^ (v >> 63)))
}

// header writes the V8 version header.
func (self *enc) header(version uint64) *enc {
	return self.tag(tagVersion).varint(version)
}

func (self *enc) oneByteString(s string) *enc {
	return self.tag(tagOneByteString).varint(uint64(len(s))).raw([]byte(s)...)
}

func (self *enc) int32(v int64) *enc {
	return self.tag(tagInt32).zigzag(v)
}

func TestVersions(t *testing.T) {
	// The same value should decode regardless of the version byte.
	for _, version := range []uint64{13, 14, 15, 17} {
		blob := (&enc{}).header(version).oneByteString("hello").buf
		v, err := Deserialize(blob)
		if err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		if v != "hello" {
			t.Fatalf("version %d: got %v", version, v)
		}
	}
}

func TestScalars(t *testing.T) {
	cases := []struct {
		name string
		blob []byte
		want interface{}
	}{
		{"int32 positive", (&enc{}).header(15).int32(42).buf, int64(42)},
		{"int32 negative", (&enc{}).header(15).int32(-7).buf, int64(-7)},
		{"uint32", (&enc{}).header(15).tag(tagUint32).varint(300).buf, int64(300)},
		{"true", (&enc{}).header(15).tag(tagTrue).buf, true},
		{"false", (&enc{}).header(15).tag(tagFalse).buf, false},
		{"null", (&enc{}).header(15).tag(tagNull).buf, nil},
		{"undefined", (&enc{}).header(15).tag(tagUndefined).buf, nil},
		// Double: 3.14 little endian.
		{"double", (&enc{}).header(15).tag(tagDouble).
			raw(0x1f, 0x85, 0xeb, 0x51, 0xb8, 0x1e, 0x09, 0x40).buf, 3.14},
		{"utf8 string", (&enc{}).header(15).tag(tagUtf8String).
			varint(3).raw('a', 'b', 'c').buf, "abc"},
		{"one byte string", (&enc{}).header(15).oneByteString("latin").buf, "latin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Deserialize(c.blob)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v (%T) want %v (%T)", got, got, c.want, c.want)
			}
		})
	}
}

func TestTwoByteString(t *testing.T) {
	// "héllo" requires non-latin1 - encode as UTF-16LE.
	u16 := []byte{'h', 0, 0xe9, 0, 'l', 0, 'l', 0, 'o', 0}
	blob := (&enc{}).header(15).tag(tagTwoByteString).
		varint(uint64(len(u16))).raw(u16...).buf
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "héllo" {
		t.Fatalf("got %q", v)
	}
}

func TestNestedObject(t *testing.T) {
	// { "user": { "name": "alice", "age": 30 }, "active": true }
	blob := (&enc{}).header(15).
		tag(tagBeginJSObject).
		oneByteString("user").
		tag(tagBeginJSObject).
		oneByteString("name").oneByteString("alice").
		oneByteString("age").int32(30).
		tag(tagEndJSObject).varint(2).
		oneByteString("active").tag(tagTrue).
		tag(tagEndJSObject).varint(2).buf

	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	d := v.(*ordereddict.Dict)
	user, _ := d.Get("user")
	ud := user.(*ordereddict.Dict)
	name, _ := ud.Get("name")
	age, _ := ud.Get("age")
	active, _ := d.Get("active")
	if name != "alice" || age != int64(30) || active != true {
		t.Fatalf("unexpected: %v", d)
	}
}

func TestDenseArrayWithProperties(t *testing.T) {
	// [10, 20] with an extra named property "label":"x"
	blob := (&enc{}).header(15).
		tag(tagBeginDenseArray).varint(2).
		int32(10).int32(20).
		oneByteString("label").oneByteString("x").
		tag(tagEndDenseArray).varint(1).varint(2).buf

	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	// With extra properties we return a dict with _elements/_properties.
	d := v.(*ordereddict.Dict)
	elems, _ := d.Get("_elements")
	if !reflect.DeepEqual(elems, []interface{}{int64(10), int64(20)}) {
		t.Fatalf("elements: %v", elems)
	}
}

func TestSparseArray(t *testing.T) {
	// sparse array length 5 with element at index 2 = "two"
	blob := (&enc{}).header(15).
		tag(tagBeginSparseArray).varint(5).
		int32(2).oneByteString("two").
		tag(tagEndSparseArray).varint(1).varint(5).buf

	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	d := v.(*ordereddict.Dict)
	got, _ := d.Get("2")
	if got != "two" {
		t.Fatalf("sparse: %v", d)
	}
}

func TestMap(t *testing.T) {
	// Map { "a" => 1, "b" => 2 }
	blob := (&enc{}).header(15).
		tag(tagBeginJSMap).
		oneByteString("a").int32(1).
		oneByteString("b").int32(2).
		tag(tagEndJSMap).varint(4).buf

	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	d := v.(*ordereddict.Dict)
	a, _ := d.Get("a")
	b, _ := d.Get("b")
	if a != int64(1) || b != int64(2) {
		t.Fatalf("map: %v", d)
	}
}

func TestSet(t *testing.T) {
	// Set { 1, 2, 3 }
	blob := (&enc{}).header(15).
		tag(tagBeginJSSet).
		int32(1).int32(2).int32(3).
		tag(tagEndJSSet).varint(3).buf

	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	arr := v.([]interface{})
	if !reflect.DeepEqual(arr, []interface{}{int64(1), int64(2), int64(3)}) {
		t.Fatalf("set: %v", arr)
	}
}

func TestObjectReference(t *testing.T) {
	// An object that contains a back-reference to itself's first child.
	// { "a": {"x":1}, "b": <ref 1> }  - ref 1 points to the {"x":1}
	// object (object id 0 is the outer object, id 1 is the inner).
	blob := (&enc{}).header(15).
		tag(tagBeginJSObject).
		oneByteString("a").
		tag(tagBeginJSObject).oneByteString("x").int32(1).
		tag(tagEndJSObject).varint(1).
		oneByteString("b").tag(tagObjectReference).varint(1).
		tag(tagEndJSObject).varint(2).buf

	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	d := v.(*ordereddict.Dict)
	a, _ := d.Get("a")
	b, _ := d.Get("b")
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("reference not resolved: a=%v b=%v", a, b)
	}
}

func TestIndexedDBDoubleWrapper(t *testing.T) {
	// Real IndexedDB layout: <value_version varint> 0xFF <blink_version>
	// 0xFF <v8_version> <data>. Decoding should transparently skip both
	// wrappers.
	body := (&enc{}).oneByteString("payload").buf
	blob := (&enc{}).
		varint(1).             // value_version
		header(0x11).          // blink: 0xFF <version>
		header(0x0f).          // v8:    0xFF <version>
		raw(body...).buf
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "payload" {
		t.Fatalf("got %v", v)
	}
}

func TestChrome102TrailerOffset(t *testing.T) {
	// Chrome 102+ inserts a 0xFE trailer-offset header (tag + 8 byte
	// offset + 4 byte size) after the version header.
	blob := (&enc{}).
		header(0x0f).
		tag(tagTrailerOffset).
		raw(0, 0, 0, 0, 0, 0, 0, 0). // 8 byte offset
		raw(0, 0, 0, 0).             // 4 byte size
		oneByteString("trailer").buf
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "trailer" {
		t.Fatalf("got %v", v)
	}
}

func TestGracefulFailure(t *testing.T) {
	// Unknown / unsupported tag should error rather than panic.
	blob := (&enc{}).header(15).tag(0x01).buf
	_, err := Deserialize(blob)
	if err == nil {
		t.Fatal("expected error on unknown tag")
	}

	// No header at all.
	_, err = Deserialize([]byte("not a v8 blob"))
	if err == nil {
		t.Fatal("expected error on missing header")
	}

	// Empty.
	_, err = Deserialize(nil)
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

// --- Original simple sanity checks retained ---

func TestStrings(t *testing.T) {
	blob := []byte{0xFF, 0x0F, 0x22, 0x05, 'h', 'e', 'l', 'l', 'o'}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "hello" {
		t.Fatalf("expected hello got %v", v)
	}
}

func TestObject(t *testing.T) {
	blob := []byte{0xFF, 0x0F, 'o', 0x22, 0x01, 'a', 'I', 0x02, '{', 0x01}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := v.(*ordereddict.Dict)
	if !ok {
		t.Fatalf("expected dict got %T", v)
	}
	got, _ := d.Get("a")
	if got != int64(1) {
		t.Fatalf("expected a=1 got %v", got)
	}
}

func TestUnwrapWrapper(t *testing.T) {
	blob := []byte{0x01, 0x00, 0xFF, 0x0F, 0x22, 0x02, 'h', 'i'}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "hi" {
		t.Fatalf("expected hi got %v", v)
	}
}
