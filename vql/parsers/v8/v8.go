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

// Package v8 implements a best-effort decoder for the V8 structured
// clone serialization format (a.k.a. SerializedScriptValue / SSV).
//
// This format is used by Chromium/Electron applications to store
// JavaScript values - most notably as the values inside IndexedDB
// records. The format is documented in V8's value-serializer.cc.
//
// The decoder handles the common JavaScript value tags (objects,
// arrays, strings, numbers, booleans, null/undefined, dates, maps and
// sets). It deliberately fails gracefully on tags it does not
// understand rather than aborting the whole decode, since the goal is
// forensic extraction of as much data as possible.
package v8

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/Velocidex/ordereddict"
)

type SerializationTag = byte

const (
	tagVersion          SerializationTag = 0xFF
	tagPadding          SerializationTag = '\x00'
	tagVerifyObjectCount SerializationTag = '?'
	tagTheHole          SerializationTag = '-'
	tagUndefined        SerializationTag = '_'
	tagNull             SerializationTag = '0'
	tagTrue             SerializationTag = 'T'
	tagFalse            SerializationTag = 'F'
	tagInt32            SerializationTag = 'I'
	tagUint32           SerializationTag = 'U'
	tagDouble           SerializationTag = 'N'
	tagBigInt           SerializationTag = 'Z'
	tagUtf8String       SerializationTag = 'S'
	tagOneByteString    SerializationTag = '"'
	tagTwoByteString    SerializationTag = 'c'
	tagObjectReference  SerializationTag = '^'
	tagBeginJSObject    SerializationTag = 'o'
	tagEndJSObject      SerializationTag = '{'
	tagBeginSparseArray SerializationTag = 'a'
	tagEndSparseArray   SerializationTag = '@'
	tagBeginDenseArray  SerializationTag = 'A'
	tagEndDenseArray    SerializationTag = '$'
	tagDate             SerializationTag = 'D'
	tagTrueObject       SerializationTag = 'y'
	tagFalseObject      SerializationTag = 'x'
	tagNumberObject     SerializationTag = 'n'
	tagBigIntObject     SerializationTag = 'z'
	tagStringObject     SerializationTag = 's'
	tagRegExp           SerializationTag = 'R'
	tagBeginJSMap       SerializationTag = ';'
	tagEndJSMap         SerializationTag = ':'
	tagBeginJSSet       SerializationTag = '\''
	tagEndJSSet         SerializationTag = ','
	tagArrayBuffer      SerializationTag = 'B'
	tagArrayBufferView  SerializationTag = 'V'
	tagSharedArrayBuf   SerializationTag = 'u'
	tagHostObject       SerializationTag = '\\'
	tagError            SerializationTag = 'r'
)

// RegExp is returned for regular expression values.
type RegExp struct {
	Pattern string `json:"Pattern"`
	Flags   int64  `json:"Flags"`
}

type decoder struct {
	data    []byte
	pos     int
	version uint32

	// Object reference table - the serializer assigns an incrementing
	// id to each object/array as it is created so later references can
	// point back to them.
	objects []interface{}

	// Guard against pathological / malformed input causing runaway
	// recursion or huge allocations.
	depth     int
	maxDepth  int
}

// Deserialize decodes a V8 structured clone blob. The input may include
// the IndexedDB value wrapper and/or the leading 0xFF version
// envelope(s); these are skipped automatically. It returns the decoded
// top level value.
func Deserialize(data []byte) (interface{}, error) {
	body, err := unwrap(data)
	if err != nil {
		return nil, err
	}

	d := &decoder{
		data:     body,
		maxDepth: 256,
	}

	// Consume the leading version header(s). The blob normally starts
	// with 0xFF <version-varint>. Some producers emit it twice.
	for d.pos < len(d.data) && d.data[d.pos] == tagVersion {
		d.pos++
		v, err := d.readVarint()
		if err != nil {
			return nil, err
		}
		d.version = uint32(v)
	}

	return d.readValue()
}

// unwrap strips the IndexedDB value wrapper (and optional Snappy
// compression) so the embedded SSV blob can be decoded. It returns the
// slice starting at the first plausible SSV header (0xFF byte).
func unwrap(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("v8: empty input")
	}

	// Already starts with the SSV version header.
	if data[0] == tagVersion {
		return data, nil
	}

	// IndexedDB stores values with a small wrapper: a varint version
	// followed by a one byte "blob type" discriminator. We probe a few
	// leading bytes for the SSV header. Limit the search window so we
	// don't accidentally treat a 0xFF inside arbitrary data as a
	// header.
	limit := 16
	if limit > len(data) {
		limit = len(data)
	}
	for i := 0; i < limit; i++ {
		if data[i] == tagVersion && i+1 < len(data) {
			// Next byte must be a small version number (varint
			// continuation bit clear, value < 0x20).
			if data[i+1] < 0x20 {
				return data[i:], nil
			}
		}
	}

	return nil, errors.New("v8: no SerializedScriptValue header found")
}

func (self *decoder) readByte() (byte, error) {
	if self.pos >= len(self.data) {
		return 0, errors.New("v8: unexpected end of data")
	}
	b := self.data[self.pos]
	self.pos++
	return b, nil
}

// readVarint reads a LEB128 unsigned varint.
func (self *decoder) readVarint() (uint64, error) {
	var result uint64
	var shift uint
	for {
		b, err := self.readByte()
		if err != nil {
			return 0, err
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 64 {
			return 0, errors.New("v8: varint too long")
		}
	}
	return result, nil
}

// readZigZag reads a zig-zag encoded signed varint (used for Int32).
func (self *decoder) readZigZag() (int64, error) {
	u, err := self.readVarint()
	if err != nil {
		return 0, err
	}
	return int64(u>>1) ^ -int64(u&1), nil
}

func (self *decoder) readBytes(n int) ([]byte, error) {
	if n < 0 || self.pos+n > len(self.data) {
		return nil, errors.New("v8: short read")
	}
	b := self.data[self.pos : self.pos+n]
	self.pos += n
	return b, nil
}

func (self *decoder) readValue() (interface{}, error) {
	self.depth++
	if self.depth > self.maxDepth {
		return nil, errors.New("v8: maximum nesting depth exceeded")
	}
	defer func() { self.depth-- }()

	tag, err := self.readByte()
	if err != nil {
		return nil, err
	}

	// Padding and version tags can appear between values.
	for tag == tagPadding || tag == tagVerifyObjectCount {
		if tag == tagVerifyObjectCount {
			_, _ = self.readVarint()
		}
		tag, err = self.readByte()
		if err != nil {
			return nil, err
		}
	}

	switch tag {
	case tagUndefined, tagTheHole:
		return nil, nil
	case tagNull:
		return nil, nil
	case tagTrue, tagTrueObject:
		return true, nil
	case tagFalse, tagFalseObject:
		return false, nil

	case tagInt32:
		return self.readZigZag()

	case tagUint32:
		v, err := self.readVarint()
		return int64(v), err

	case tagDouble, tagNumberObject, tagDate:
		b, err := self.readBytes(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), nil

	case tagBigInt, tagBigIntObject:
		return self.readBigInt()

	case tagUtf8String:
		return self.readUtf8String()

	case tagOneByteString, tagStringObject:
		return self.readOneByteString()

	case tagTwoByteString:
		return self.readTwoByteString()

	case tagBeginJSObject:
		return self.readJSObject()

	case tagBeginDenseArray:
		return self.readDenseArray()

	case tagBeginSparseArray:
		return self.readSparseArray()

	case tagBeginJSMap:
		return self.readJSMap()

	case tagBeginJSSet:
		return self.readJSSet()

	case tagObjectReference:
		id, err := self.readVarint()
		if err != nil {
			return nil, err
		}
		if int(id) < len(self.objects) {
			return self.objects[id], nil
		}
		return nil, nil

	case tagRegExp:
		pattern, err := self.readValue()
		if err != nil {
			return nil, err
		}
		flags, err := self.readVarint()
		if err != nil {
			return nil, err
		}
		s, _ := pattern.(string)
		return &RegExp{Pattern: s, Flags: int64(flags)}, nil

	case tagArrayBuffer:
		length, err := self.readVarint()
		if err != nil {
			return nil, err
		}
		return self.readBytes(int(length))

	default:
		return nil, fmt.Errorf("v8: unsupported tag 0x%02x (%q) at offset %d",
			tag, string(rune(tag)), self.pos-1)
	}
}

func (self *decoder) readBigInt() (interface{}, error) {
	// BitField: bit 0 = sign, remaining bits = byte length.
	bitfield, err := self.readVarint()
	if err != nil {
		return nil, err
	}
	negative := bitfield&1 != 0
	byteLength := int(bitfield >> 1)
	digits, err := self.readBytes(byteLength)
	if err != nil {
		return nil, err
	}
	// Reconstruct as a decimal string (little endian digits).
	var value uint64
	for i := 0; i < len(digits) && i < 8; i++ {
		value |= uint64(digits[i]) << (8 * uint(i))
	}
	if negative {
		return fmt.Sprintf("-%d", value), nil
	}
	return fmt.Sprintf("%d", value), nil
}

func (self *decoder) readUtf8String() (string, error) {
	length, err := self.readVarint()
	if err != nil {
		return "", err
	}
	b, err := self.readBytes(int(length))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (self *decoder) readOneByteString() (string, error) {
	length, err := self.readVarint()
	if err != nil {
		return "", err
	}
	b, err := self.readBytes(int(length))
	if err != nil {
		return "", err
	}
	// Latin-1 -> UTF-8
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes), nil
}

func (self *decoder) readTwoByteString() (string, error) {
	length, err := self.readVarint()
	if err != nil {
		return "", err
	}
	b, err := self.readBytes(int(length))
	if err != nil {
		return "", err
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16)), nil
}

func (self *decoder) readJSObject() (interface{}, error) {
	result := ordereddict.NewDict()
	self.objects = append(self.objects, result)

	for {
		if self.pos >= len(self.data) {
			return nil, errors.New("v8: truncated object")
		}
		if self.data[self.pos] == tagEndJSObject {
			self.pos++
			break
		}

		key, err := self.readValue()
		if err != nil {
			return nil, err
		}
		value, err := self.readValue()
		if err != nil {
			return nil, err
		}
		result.Set(keyToString(key), value)
	}

	// Trailing property count.
	_, _ = self.readVarint()
	return result, nil
}

func (self *decoder) readDenseArray() (interface{}, error) {
	length, err := self.readVarint()
	if err != nil {
		return nil, err
	}
	if length > uint64(len(self.data)) {
		return nil, errors.New("v8: dense array length too large")
	}
	result := make([]interface{}, 0, length)
	self.objects = append(self.objects, &result)

	for i := uint64(0); i < length; i++ {
		v, err := self.readValue()
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}

	// Any additional named properties follow until the end tag.
	props := ordereddict.NewDict()
	hasProps := false
	for self.pos < len(self.data) && self.data[self.pos] != tagEndDenseArray {
		key, err := self.readValue()
		if err != nil {
			return nil, err
		}
		value, err := self.readValue()
		if err != nil {
			return nil, err
		}
		props.Set(keyToString(key), value)
		hasProps = true
	}
	if self.pos < len(self.data) {
		self.pos++ // consume tagEndDenseArray
	}
	_, _ = self.readVarint() // property count
	_, _ = self.readVarint() // length

	if hasProps {
		return ordereddict.NewDict().
			Set("_elements", result).
			Set("_properties", props), nil
	}
	return result, nil
}

func (self *decoder) readSparseArray() (interface{}, error) {
	length, err := self.readVarint()
	if err != nil {
		return nil, err
	}
	_ = length
	result := ordereddict.NewDict()
	self.objects = append(self.objects, result)

	for self.pos < len(self.data) && self.data[self.pos] != tagEndSparseArray {
		key, err := self.readValue()
		if err != nil {
			return nil, err
		}
		value, err := self.readValue()
		if err != nil {
			return nil, err
		}
		result.Set(keyToString(key), value)
	}
	if self.pos < len(self.data) {
		self.pos++ // consume tagEndSparseArray
	}
	_, _ = self.readVarint() // property count
	_, _ = self.readVarint() // length
	return result, nil
}

func (self *decoder) readJSMap() (interface{}, error) {
	result := ordereddict.NewDict()
	self.objects = append(self.objects, result)

	for self.pos < len(self.data) && self.data[self.pos] != tagEndJSMap {
		key, err := self.readValue()
		if err != nil {
			return nil, err
		}
		value, err := self.readValue()
		if err != nil {
			return nil, err
		}
		result.Set(keyToString(key), value)
	}
	if self.pos < len(self.data) {
		self.pos++ // consume tagEndJSMap
	}
	_, _ = self.readVarint() // 2 * number of entries
	return result, nil
}

func (self *decoder) readJSSet() (interface{}, error) {
	var result []interface{}
	self.objects = append(self.objects, &result)

	for self.pos < len(self.data) && self.data[self.pos] != tagEndJSSet {
		v, err := self.readValue()
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	if self.pos < len(self.data) {
		self.pos++ // consume tagEndJSSet
	}
	_, _ = self.readVarint() // number of entries
	return result, nil
}

func keyToString(key interface{}) string {
	switch t := key.(type) {
	case string:
		return t
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
