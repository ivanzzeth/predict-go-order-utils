package utils

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/predict-go-order-utils/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestGetVerifyingContractAddress(t *testing.T) {
	// BNB Chain mainnet
	contract, err := GetVerifyingContractAddress(big.NewInt(56), model.CTFExchange)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToAddress("0x8BC070BEdAB741406F4B1Eb65A72bee27894B689").Hex(), contract.Hex())

	// wrong network
	_, err = GetVerifyingContractAddress(big.NewInt(1), model.CTFExchange)
	assert.Error(t, err)

	_, err = GetVerifyingContractAddress(big.NewInt(1), model.NegRiskCTFExchange)
	assert.Error(t, err)
}
