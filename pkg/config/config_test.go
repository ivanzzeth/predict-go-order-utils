package config

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestGetContracts(t *testing.T) {
	var (
		bnbChain = &Contracts{
			Exchange:         common.HexToAddress("0x8BC070BEdAB741406F4B1Eb65A72bee27894B689"),
			NegRiskExchange:  common.HexToAddress("0x365fb81bd4A24D6303cd2F19c349dE6894D8d58A"),
			NegRiskAdapter:   common.HexToAddress("0xc3Cf7c252f65E0d8D88537dF96569AE94a7F1A6E"),
			Collateral:       common.HexToAddress("0x55d398326f99059fF775485246999027B3197955"),
			Conditional:      common.HexToAddress("0x22DA1810B194ca018378464a58f6Ac2B10C9d244"),
		}
	)

	c, err := GetContracts(56)
	assert.NotNil(t, c)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(c.Exchange[:], bnbChain.Exchange[:]))
	assert.True(t, bytes.Equal(c.NegRiskExchange[:], bnbChain.NegRiskExchange[:]))
	assert.True(t, bytes.Equal(c.NegRiskAdapter[:], bnbChain.NegRiskAdapter[:]))
	assert.True(t, bytes.Equal(c.Collateral[:], bnbChain.Collateral[:]))
	assert.True(t, bytes.Equal(c.Conditional[:], bnbChain.Conditional[:]))

	// Invalid chain ID
	c, err = GetContracts(100000)
	assert.Nil(t, c)
	assert.NotNil(t, err)
}
