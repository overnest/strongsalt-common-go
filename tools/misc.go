package tools

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
