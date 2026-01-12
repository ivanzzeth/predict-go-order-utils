package builder

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/predict-go-order-utils/pkg/model"
	predictcontracts "github.com/ivanzzeth/predict-go-contracts"
	"github.com/stretchr/testify/assert"
)

var (
	chainId = new(big.Int).SetInt64(56) // BNB Chain mainnet
	// publicly known private key
	privateKey, _ = crypto.ToECDSA(common.Hex2Bytes("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"))
	// private key address
	signerAddress = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

	salt = int64(479249096354)

	// Exchange addresses for testing (from config)
	ctfExchangeAddr, _        = ExchangeAddressFromContract(chainId, model.CTFExchange)
	negRiskCtfExchangeAddr, _ = ExchangeAddressFromContract(chainId, model.NegRiskCTFExchange)
)

func TestBuildOrder(t *testing.T) {
	// random salt
	builder := NewExchangeOrderBuilderImpl(chainId, nil)

	order, err := builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       "0x0",
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	assert.True(t, order.Salt.Int64() > 0)
	assert.Equal(t, order.Maker, signerAddress)
	assert.Equal(t, order.Signer, signerAddress)
	assert.Equal(t, order.Taker, common.HexToAddress("0x0"))
	assert.Equal(t, order.TokenId.String(), "1234")
	assert.Equal(t, order.MakerAmount.String(), "100000000")
	assert.Equal(t, order.TakerAmount.String(), "50000000")
	assert.Equal(t, order.Side.String(), "0")
	assert.Equal(t, order.Expiration.String(), "0")
	assert.Equal(t, order.Nonce.String(), "0")
	assert.Equal(t, order.FeeRateBps.String(), "100")
	assert.Equal(t, order.SignatureType.String(), "0")

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       "0x1",
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	assert.Equal(t, order.Salt.Int64(), int64(salt))
	assert.Equal(t, order.Maker, signerAddress)
	assert.Equal(t, order.Signer, signerAddress)
	assert.Equal(t, order.Taker, common.HexToAddress("0x1"))
	assert.Equal(t, order.TokenId.String(), "1234")
	assert.Equal(t, order.MakerAmount.String(), "100000000")
	assert.Equal(t, order.TakerAmount.String(), "50000000")
	assert.Equal(t, order.Side.String(), "0")
	assert.Equal(t, order.Expiration.String(), "0")
	assert.Equal(t, order.Nonce.String(), "0")
	assert.Equal(t, order.FeeRateBps.String(), "100")
	assert.Equal(t, order.SignatureType.String(), "0")
}

func TestBuildOrderHash(t *testing.T) {
	// CTF Exchange
	// random salt
	builder := NewExchangeOrderBuilderImpl(chainId, nil)

	order, err := builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err := builder.BuildOrderHash(order, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err = builder.BuildOrderHash(order, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)
	t.Logf("CTF Exchange order hash: %s", orderHash.Hex())

	// NegRisk Exchange
	// random salt
	builder = NewExchangeOrderBuilderImpl(chainId, nil)

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err = builder.BuildOrderHash(order, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err = builder.BuildOrderHash(order, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)
	t.Logf("NegRisk Exchange order hash: %s", orderHash.Hex())
}

func TestBuildOrderSignature(t *testing.T) {
	// CTF Exchange
	// random salt
	builder := NewExchangeOrderBuilderImpl(chainId, nil)
	ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)

	order, err := builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err := builder.BuildOrderHash(order, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)

	orderSignature, err := builder.BuildOrderSignature(ethSigner, order, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderSignature)

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err = builder.BuildOrderHash(order, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)

	orderSignature, err = builder.BuildOrderSignature(ethSigner, order, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderSignature)
	t.Logf("CTF Exchange signature: %s", common.Bytes2Hex(orderSignature))

	// NegRisk Exchange
	// random salt
	builder = NewExchangeOrderBuilderImpl(chainId, nil)

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err = builder.BuildOrderHash(order, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)

	orderSignature, err = builder.BuildOrderSignature(ethSigner, order, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderSignature)

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	order, err = builder.BuildOrder(&model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	})
	assert.NoError(t, err)
	assert.NotNil(t, order)

	orderHash, err = builder.BuildOrderHash(order, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderHash)

	orderSignature, err = builder.BuildOrderSignature(ethSigner, order, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, orderSignature)
	t.Logf("NegRisk Exchange signature: %s", common.Bytes2Hex(orderSignature))
}

func TestBuildSignedOrder(t *testing.T) {
	// CTF Exchange
	// random salt
	builder := NewExchangeOrderBuilderImpl(chainId, nil)
	ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)

	signedOrder, err := builder.BuildSignedOrder(ethSigner, &model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	}, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, signedOrder)

	assert.True(t, signedOrder.Salt.Int64() > 0)
	assert.Equal(t, signedOrder.Maker, signerAddress)
	assert.Equal(t, signedOrder.Signer, signerAddress)
	assert.Equal(t, signedOrder.TokenId.String(), "1234")
	assert.Equal(t, signedOrder.MakerAmount.String(), "100000000")
	assert.Equal(t, signedOrder.TakerAmount.String(), "50000000")
	assert.Equal(t, signedOrder.Side.String(), "0")
	assert.Equal(t, signedOrder.Expiration.String(), "0")
	assert.Equal(t, signedOrder.Nonce.String(), "0")
	assert.Equal(t, signedOrder.FeeRateBps.String(), "100")
	assert.Equal(t, signedOrder.SignatureType.String(), "0")
	assert.NotEmpty(t, signedOrder.Signature)
	assert.NotEmpty(t, hex.EncodeToString(signedOrder.Signature))

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	signedOrder, err = builder.BuildSignedOrder(ethSigner, &model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	}, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, signedOrder)

	assert.Equal(t, signedOrder.Salt.Int64(), salt)
	assert.Equal(t, signedOrder.Maker, signerAddress)
	assert.Equal(t, signedOrder.Signer, signerAddress)
	assert.Equal(t, signedOrder.TokenId.String(), "1234")
	assert.Equal(t, signedOrder.MakerAmount.String(), "100000000")
	assert.Equal(t, signedOrder.TakerAmount.String(), "50000000")
	assert.Equal(t, signedOrder.Side.String(), "0")
	assert.Equal(t, signedOrder.Expiration.String(), "0")
	assert.Equal(t, signedOrder.Nonce.String(), "0")
	assert.Equal(t, signedOrder.FeeRateBps.String(), "100")
	assert.Equal(t, signedOrder.SignatureType.String(), "0")
	assert.NotEmpty(t, hex.EncodeToString(signedOrder.Signature))
	t.Logf("CTF Exchange signed order signature: %s", common.Bytes2Hex(signedOrder.Signature))

	// NegRisk Exchange
	// random salt
	builder = NewExchangeOrderBuilderImpl(chainId, nil)

	signedOrder, err = builder.BuildSignedOrder(ethSigner, &model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	}, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, signedOrder)

	assert.True(t, signedOrder.Salt.Int64() > 0)
	assert.Equal(t, signedOrder.Maker, signerAddress)
	assert.Equal(t, signedOrder.Signer, signerAddress)
	assert.Equal(t, signedOrder.TokenId.String(), "1234")
	assert.Equal(t, signedOrder.MakerAmount.String(), "100000000")
	assert.Equal(t, signedOrder.TakerAmount.String(), "50000000")
	assert.Equal(t, signedOrder.Side.String(), "0")
	assert.Equal(t, signedOrder.Expiration.String(), "0")
	assert.Equal(t, signedOrder.Nonce.String(), "0")
	assert.Equal(t, signedOrder.FeeRateBps.String(), "100")
	assert.Equal(t, signedOrder.SignatureType.String(), "0")
	assert.NotEmpty(t, signedOrder.Signature)
	assert.NotEmpty(t, hex.EncodeToString(signedOrder.Signature))

	// specific salt
	builder = NewExchangeOrderBuilderImpl(chainId, func() int64 { return salt })

	signedOrder, err = builder.BuildSignedOrder(ethSigner, &model.OrderData{
		Maker:       signerAddress.Hex(),
		Taker:       common.HexToAddress("0x0").Hex(),
		TokenId:     "1234",
		MakerAmount: "100000000",
		TakerAmount: "50000000",
		Side:        model.BUY,
		FeeRateBps:  "100",
		Nonce:       "0",
	}, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, signedOrder)

	assert.Equal(t, signedOrder.Salt.Int64(), salt)
	assert.Equal(t, signedOrder.Maker, signerAddress)
	assert.Equal(t, signedOrder.Signer, signerAddress)
	assert.Equal(t, signedOrder.TokenId.String(), "1234")
	assert.Equal(t, signedOrder.MakerAmount.String(), "100000000")
	assert.Equal(t, signedOrder.TakerAmount.String(), "50000000")
	assert.Equal(t, signedOrder.Side.String(), "0")
	assert.Equal(t, signedOrder.Expiration.String(), "0")
	assert.Equal(t, signedOrder.Nonce.String(), "0")
	assert.Equal(t, signedOrder.FeeRateBps.String(), "100")
	assert.Equal(t, signedOrder.SignatureType.String(), "0")
	assert.NotEmpty(t, hex.EncodeToString(signedOrder.Signature))
	t.Logf("NegRisk Exchange signed order signature: %s", common.Bytes2Hex(signedOrder.Signature))
}

func TestBuildSignedOrder2(t *testing.T) {
	builder := NewExchangeOrderBuilderImpl(chainId, nil)
	ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)

	signedOrder, err := builder.BuildSignedOrder(ethSigner, &model.OrderData{
		Maker:         "0xaFB8270A801862270FebB3763505b136491e557b",
		Signer:        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Taker:         common.HexToAddress("0x0").Hex(),
		TokenId:       "100",
		MakerAmount:   "50000000",
		TakerAmount:   "100000000",
		Side:          model.BUY,
		FeeRateBps:    "100",
		Nonce:         "0",
		Expiration:    "0",
		SignatureType: predictcontracts.SignatureTypeEOA,
	}, negRiskCtfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, signedOrder)
}

// TestBuildSignedOrderPredictBNBChain tests order signing for Predict on BNB Chain
func TestBuildSignedOrderPredictBNBChain(t *testing.T) {
	// BNB Chain mainnet
	bnbChainId := new(big.Int).SetInt64(56)
	// Use fixed salt = 1
	builder := NewExchangeOrderBuilderImpl(bnbChainId, func() int64 { return 1 })
	ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)

	// Verify signer address
	signerAddr := ethSigner.GetAddress()
	assert.Equal(t, signerAddress, signerAddr, "invalid signer address")

	signedOrder, err := builder.BuildSignedOrder(ethSigner, &model.OrderData{
		Maker:         "0x8edbd5d17f368a50a7f8c0b1bbc0c9fcd0c2ccb3",
		Taker:         common.HexToAddress("0x0").Hex(),
		TokenId:       "102955147056674320605625831094933410586073394253729381009399467166952809400644",
		MakerAmount:   "50",
		TakerAmount:   "100",
		Side:          model.BUY,
		FeeRateBps:    "0",
		Nonce:         "0",
		Signer:        signerAddress.Hex(),
		SignatureType: predictcontracts.SignatureTypeEOA,
	}, ctfExchangeAddr)
	assert.NoError(t, err)
	assert.NotNil(t, signedOrder)

	// Verify order fields
	assert.Equal(t, int64(1), signedOrder.Salt.Int64())
	assert.Equal(t, common.HexToAddress("0x8edbd5d17f368a50a7f8c0b1bbc0c9fcd0c2ccb3"), signedOrder.Maker)
	assert.Equal(t, signerAddress, signedOrder.Signer)
	assert.Equal(t, common.HexToAddress("0x0"), signedOrder.Taker)
	assert.Equal(t, "102955147056674320605625831094933410586073394253729381009399467166952809400644", signedOrder.TokenId.String())
	assert.Equal(t, "50", signedOrder.MakerAmount.String())
	assert.Equal(t, "100", signedOrder.TakerAmount.String())
	assert.Equal(t, "0", signedOrder.Side.String())
	assert.Equal(t, "0", signedOrder.FeeRateBps.String())
	assert.NotEmpty(t, signedOrder.Signature)

	actualSignature := common.Bytes2Hex(signedOrder.Signature)
	t.Logf("Predict BNB Chain signature: %s", actualSignature)
}
