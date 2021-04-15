package convert

import (
	"fmt"
	"strconv"
)

// ToString returns the string representation of the value
func ToString(v interface{}) string {
	switch tv := v.(type) {
	case string:
		return tv
	case fmt.Stringer:
		return tv.String()
	case bool:
		return strconv.FormatBool(tv)
	case uint:
		return strconv.FormatUint(uint64(tv), 10)
	case uint8:
		return strconv.FormatUint(uint64(tv), 10)
	case uint16:
		return strconv.FormatUint(uint64(tv), 10)
	case uint32:
		return strconv.FormatUint(uint64(tv), 10)
	case uint64:
		return strconv.FormatUint(tv, 10)
	case int:
		return strconv.FormatInt(int64(tv), 10)
	case int8:
		return strconv.FormatInt(int64(tv), 10)
	case int16:
		return strconv.FormatInt(int64(tv), 10)
	case int32:
		return strconv.FormatInt(int64(tv), 10)
	case int64:
		return strconv.FormatInt(tv, 10)
	case float32:
		return strconv.FormatFloat(float64(tv), 'f', -1, 64)
	case float64:
		return strconv.FormatFloat(tv, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", tv)
	}
}
