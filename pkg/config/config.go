package config

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type Contracts struct {
	Exchange         common.Address
	NegRiskExchange  common.Address
	NegRiskAdapter   common.Address
	Collateral       common.Address
	Conditional      common.Address
}

var (
	// BNB Chain Mainnet (Chain ID: 56)
	_BNB_CHAIN_CONTRACTS = &Contracts{
		Exchange:         common.HexToAddress("0x8BC070BEdAB741406F4B1Eb65A72bee27894B689"),
		NegRiskExchange:  common.HexToAddress("0x365fb81bd4A24D6303cd2F19c349dE6894D8d58A"),
		NegRiskAdapter:   common.HexToAddress("0xc3Cf7c252f65E0d8D88537dF96569AE94a7F1A6E"),
		Collateral:       common.HexToAddress("0x55d398326f99059fF775485246999027B3197955"), // USDT
		Conditional:      common.HexToAddress("0x22DA1810B194ca018378464a58f6Ac2B10C9d244"),
	}

	// BNB Chain Testnet (Chain ID: 97)
	_BNB_TESTNET_CONTRACTS = &Contracts{
		Exchange:         common.HexToAddress("0x2A6413639BD3d73a20ed8C95F634Ce198ABbd2d7"),
		NegRiskExchange:  common.HexToAddress("0xd690b2bd441bE36431F6F6639D7Ad351e7B29680"),
		NegRiskAdapter:   common.HexToAddress("0x285c1B939380B130D7EBd09467b93faD4BA623Ed"),
		Collateral:       common.HexToAddress("0x337610d27c682E347C9cD60BD4b3b107C9d34dDd"), // USDT
		Conditional:      common.HexToAddress("0x2827AAef52D71910E8FBad2FfeBC1B6C2DA37743"),
	}
)

func GetContracts(chainId int64) (*Contracts, error) {
	switch chainId {
	case 56:
		return _BNB_CHAIN_CONTRACTS, nil
	case 97:
		return _BNB_TESTNET_CONTRACTS, nil
	default:
		return nil, fmt.Errorf("invalid chain id: %d, only BNB (56) and BNB Testnet (97) are supported", chainId)
	}
}
