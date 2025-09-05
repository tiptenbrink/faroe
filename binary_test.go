package faroe

import (
	"math"
	"slices"
	"testing"
)

func TestBinarySequenceBytesEncoderAndParser(t *testing.T) {
	binarySequence := binarySequenceType{}

	b := make([]byte, 1000)
	b[0] = 1
	b[999] = 1
	binarySequence.add([]byte{})
	binarySequence.add(b)
	binarySequence.addString("")
	binarySequence.addString("Hello World!🐏🐑")
	binarySequence.addInt32(0)
	binarySequence.addInt32(math.MaxInt32)
	binarySequence.addInt32(math.MinInt32)
	binarySequence.addInt64(0)
	binarySequence.addInt64(math.MaxInt64)
	binarySequence.addInt64(math.MinInt64)
	binarySequence.addBool(true)
	binarySequence.addBool(false)

	encoded := binarySequence.encode()

	decoded, err := parseBinarySequenceBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}

	bytesItem, err := decoded.get(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytesItem) != 0 {
		t.Fatal("bytes at index 0 did not match expected value")
	}
	bytesItem, err = decoded.get(1)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Compare(bytesItem, b) != 0 {
		t.Fatal("bytes at index 1 did not match expected value")
	}

	stringItem, err := decoded.getString(2)
	if err != nil {
		t.Fatal(err)
	}
	if stringItem != "" {
		t.Fatal("string at index 2 did not match expected value")
	}
	stringItem, err = decoded.getString(3)
	if err != nil {
		t.Fatal(err)
	}
	if stringItem != "Hello World!🐏🐑" {
		t.Fatal("string at index 3 did not match expected value")
	}

	int32Item, err := decoded.getInt32(4)
	if err != nil {
		t.Fatal(err)
	}
	if int32Item != 0 {
		t.Fatal("int32 at index 4 did not match expected value")
	}
	int32Item, err = decoded.getInt32(5)
	if err != nil {
		t.Fatal(err)
	}
	if int32Item != math.MaxInt32 {
		t.Fatal("int32 at index 5 did not match expected value")
	}
	int32Item, err = decoded.getInt32(6)
	if err != nil {
		t.Fatal(err)
	}
	if int32Item != math.MinInt32 {
		t.Fatal("int32 at index 6 did not match expected value")
	}

	int64Item, err := decoded.getInt64(7)
	if err != nil {
		t.Fatal(err)
	}
	if int64Item != 0 {
		t.Fatal("int64 at index 7 did not match expected value")
	}
	int64Item, err = decoded.getInt64(8)
	if err != nil {
		t.Fatal(err)
	}
	if int64Item != math.MaxInt64 {
		t.Fatal("int64 at index 8 did not match expected value")
	}
	int64Item, err = decoded.getInt64(9)
	if err != nil {
		t.Fatal(err)
	}
	if int64Item != math.MinInt64 {
		t.Fatal("int64 at index 9 did not match expected value")
	}

	boolItem, err := decoded.getBool(10)
	if err != nil {
		t.Fatal(err)
	}
	if !boolItem {
		t.Fatal("bool at index 10 did not match expected value")
	}
	boolItem, err = decoded.getBool(11)
	if err != nil {
		t.Fatal(err)
	}
	if boolItem {
		t.Fatal("bool at index 11 did not match expected value")
	}
}
