package tools

import "encoding/json"

// MaxUint32 returns the bigger value between two uint32 numbers
func MaxUint32(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}

// MinUint32 returns the smaller value between two uint32 numbers
func MinUint32(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

// BinarySearchU64 finds a number in a sorted list.
// Returns the index where the value is found.
// Returns -1 if value is not found
func BinarySearchU64(list []uint64, val uint64) int {
	if list == nil || len(list) == 0 {
		return -1
	}

	left := 0
	right := len(list) - 1
	for true {
		mid := (left + right) / 2
		if list[mid] == val {
			return mid
		}

		// Can't find the value
		if left == right {
			return -1
		}

		if list[mid] > val {
			if mid > left {
				right = mid - 1
			} else {
				right = left
			}
		} else {
			if mid < right {
				left = mid + 1
			} else {
				left = right
			}
		}
	}

	return -1
}


func Marshal(data interface{}) ([]byte, error){
	return json.Marshal(data)
}

func Unmarshal( data []byte, v interface{}) error{
	return json.Unmarshal(data, v)
}