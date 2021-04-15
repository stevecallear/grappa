package convert_test

import (
	"testing"
	"time"

	"github.com/stevecallear/grappa/internal/convert"
)

func TestToString(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		exp   string
	}{
		{
			name:  "string",
			input: "expected",
			exp:   "expected",
		},
		{
			name:  "Stringer",
			input: time.Date(2021, 6, 4, 9, 13, 12, 0, time.UTC),
			exp:   "2021-06-04 09:13:12 +0000 UTC",
		},
		{
			name:  "bool",
			input: true,
			exp:   "true",
		},
		{
			name:  "uint",
			input: uint(123),
			exp:   "123",
		},
		{
			name:  "uint8",
			input: uint8(123),
			exp:   "123",
		},
		{
			name:  "uint16",
			input: uint16(123),
			exp:   "123",
		},
		{
			name:  "uint32",
			input: uint32(123),
			exp:   "123",
		},
		{
			name:  "uint64",
			input: uint64(123),
			exp:   "123",
		},
		{
			name:  "int",
			input: int(123),
			exp:   "123",
		},
		{
			name:  "int8",
			input: int8(123),
			exp:   "123",
		},
		{
			name:  "int16",
			input: int16(123),
			exp:   "123",
		},
		{
			name:  "int32",
			input: int32(123),
			exp:   "123",
		},
		{
			name:  "int64",
			input: int64(123),
			exp:   "123",
		},
		{
			name:  "float32",
			input: float32(123.123),
			exp:   "123.12300109863281", // floating point precision
		},
		{
			name:  "float64",
			input: float64(123.123),
			exp:   "123.123",
		},
		{
			name: "other",
			input: struct {
				V string
			}{
				V: "expected",
			},
			exp: "{expected}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act := convert.ToString(tt.input)
			if act != tt.exp {
				t.Errorf("got %s, expected %s", act, tt.exp)
			}
		})
	}
}
