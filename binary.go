package faroe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

func (binarySequence *binarySequenceType) encode() []byte {
	buffer := bytes.Buffer{}
	itemSizeBytes := [10]byte{}
	for _, item := range *binarySequence {
		itemSizeBytesSize := binary.PutUvarint(itemSizeBytes[:], uint64(len(item)))
		buffer.Write(itemSizeBytes[:itemSizeBytesSize])
		buffer.Write(item)
	}

	return buffer.Bytes()
}

func (binarySequence *binarySequenceType) add(value []byte) {
	*binarySequence = append(*binarySequence, value)
}

func (binarySequence *binarySequenceType) addString(value string) {
	binarySequence.add([]byte(value))
}

func (binarySequence *binarySequenceType) addInt64(value int64) {
	valueUint64 := uint64(value) << 1
	if value < 0 {
		valueUint64 = ^valueUint64
	}
	encoded := [8]byte{}
	binary.BigEndian.PutUint64(encoded[:], valueUint64)

	offset := 0
	for _, b := range encoded {
		if b != 0 {
			break
		}
		offset++
	}
	binarySequence.add(encoded[offset:])
}

func (binarySequence *binarySequenceType) addInt32(value int32) {
	valueUint32 := uint32(value) << 1
	if value < 0 {
		valueUint32 = ^valueUint32
	}
	encoded := [4]byte{}
	binary.BigEndian.PutUint32(encoded[:], valueUint32)

	offset := 0
	for _, b := range encoded {
		if b != 0 {
			break
		}
		offset++
	}
	binarySequence.add(encoded[offset:])
}

func (binarySequence *binarySequenceType) addBool(value bool) {
	if value {
		binarySequence.add([]byte{1})
	} else {
		binarySequence.add([]byte{0})
	}
}

func parseBinarySequenceBytes(encoded []byte) (binarySequenceType, error) {
	binarySequence := binarySequenceType{}
	offset := 0
	for offset < len(encoded) {
		sizeUint64, bytesRead := binary.Uvarint(encoded[offset:])
		if bytesRead < 1 {
			return nil, fmt.Errorf("invalid item length header")
		}
		offset += int(bytesRead)
		if sizeUint64 > math.MaxInt {
			return nil, fmt.Errorf("item size too big")
		}
		size := int(sizeUint64)
		if offset+size > len(encoded) {
			return nil, fmt.Errorf("item size too big")
		}
		binarySequence = append(binarySequence, encoded[offset:offset+int(size)])
		offset += int(size)
	}

	return binarySequence, nil
}

type binarySequenceType [][]byte

func (binarySequence *binarySequenceType) get(index int) ([]byte, error) {
	if index >= len(*binarySequence) {
		return nil, fmt.Errorf("out of range")
	}
	value := (*binarySequence)[index]
	return value, nil
}

func (binarySequence *binarySequenceType) getString(index int) (string, error) {
	encoded, err := binarySequence.get(index)
	if err != nil {
		return "", fmt.Errorf("failed to get value: %s", err.Error())
	}
	return string(encoded), nil
}

func (binarySequence *binarySequenceType) getInt64(index int) (int64, error) {
	encoded, err := binarySequence.get(index)
	if err != nil {
		return 0, fmt.Errorf("failed to get value: %s", err.Error())
	}
	if len(encoded) > 8 {
		return 0, errors.New("invalid int64 encoding")
	}
	encodedUint64 := [8]byte{}
	copy(encodedUint64[8-len(encoded):], encoded)
	decodedUint64 := binary.BigEndian.Uint64(encodedUint64[:])
	decoded := int64(decodedUint64 >> 1)
	if decodedUint64&1 == 1 {
		decoded = ^decoded
	}
	return decoded, nil
}

func (binarySequence *binarySequenceType) getInt32(index int) (int32, error) {
	encoded, err := binarySequence.get(index)
	if err != nil {
		return 0, fmt.Errorf("failed to get value: %s", err.Error())
	}
	if len(encoded) > 4 {
		return 0, errors.New("invalid int64 encoding")
	}
	encodedUint32 := [4]byte{}
	copy(encodedUint32[4-len(encoded):], encoded)
	decodedUint32 := binary.BigEndian.Uint32(encodedUint32[:])
	decoded := int32(decodedUint32 >> 1)
	if decodedUint32&1 == 1 {
		decoded = ^decoded
	}
	return decoded, nil
}

func (binarySequence *binarySequenceType) getBool(index int) (bool, error) {
	encoded, err := binarySequence.get(index)
	if err != nil {
		return false, fmt.Errorf("failed to get value: %s", err.Error())
	}
	if len(encoded) != 1 {
		return false, errors.New("invalid bool encoding")
	}
	if encoded[0] == 0 {
		return false, nil
	}
	if encoded[0] == 1 {
		return true, nil
	}
	return false, errors.New("invalid bool encoding")
}
