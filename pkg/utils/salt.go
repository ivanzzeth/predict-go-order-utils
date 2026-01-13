package utils

import (
	"crypto/rand"
	"math/big"
)

func GenerateRandomSalt() int64 {
	// API requires salt to be between 0 and 2147483648 (2^31)
	maxInt := int64(2147483648) // 2^31
	nBig, _ := rand.Int(rand.Reader, big.NewInt(maxInt))
	return nBig.Int64()
}
