package v8

import (
	"reflect"
	"testing"

	"github.com/Velocidex/ordereddict"
)

func TestStrings(t *testing.T) {
	// FF 0F (version 15) "hello" as one byte string: 22 05 'hello'
	blob := []byte{0xFF, 0x0F, 0x22, 0x05, 'h', 'e', 'l', 'l', 'o'}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "hello" {
		t.Fatalf("expected hello got %v", v)
	}
}

func TestInt32(t *testing.T) {
	// version, int32 tag 'I', zigzag(1)=2
	blob := []byte{0xFF, 0x0F, 'I', 0x02}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != int64(1) {
		t.Fatalf("expected 1 got %v", v)
	}

	// zigzag(-1) = 1
	blob = []byte{0xFF, 0x0F, 'I', 0x01}
	v, _ = Deserialize(blob)
	if v != int64(-1) {
		t.Fatalf("expected -1 got %v", v)
	}
}

func TestObject(t *testing.T) {
	// { "a": 1 }
	// o, key 'a' (22 01 61), value 'I' 02, end '{', count 01
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

func TestDenseArray(t *testing.T) {
	// [1, 2] : A 02 I 02 I 04 $ 00 02
	blob := []byte{0xFF, 0x0F, 'A', 0x02, 'I', 0x02, 'I', 0x04, '$', 0x00, 0x02}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := v.([]interface{})
	if !ok {
		t.Fatalf("expected slice got %T", v)
	}
	if !reflect.DeepEqual(arr, []interface{}{int64(1), int64(2)}) {
		t.Fatalf("unexpected array %v", arr)
	}
}

func TestUnwrapWrapper(t *testing.T) {
	// Simulate an IndexedDB wrapper: version varint 0x01, blob type
	// 0x00, then the SSV blob.
	blob := []byte{0x01, 0x00, 0xFF, 0x0F, 0x22, 0x02, 'h', 'i'}
	v, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if v != "hi" {
		t.Fatalf("expected hi got %v", v)
	}
}
