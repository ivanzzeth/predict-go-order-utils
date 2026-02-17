package config

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type Contracts struct {
	Exchange                  common.Address
	NegRiskExchange           common.Address
	NegRiskAdapter            common.Address
	Collateral                common.Address
	Conditional               common.Address
	YieldBearingExchange      common.Address
	YieldBearingNegRiskExchange common.Address
}

var (
	// BNB Chain Mainnet (Chain ID: 56)
	_BNB_CHAIN_CONTRACTS = &Contracts{
		Exchange:                    common.HexToAddress("0x8BC070BEdAB741406F4B1Eb65A72bee27894B689"),
		NegRiskExchange:             common.HexToAddress("0x365fb81bd4A24D6303cd2F19c349dE6894D8d58A"),
		NegRiskAdapter:              common.HexToAddress("0xc3Cf7c252f65E0d8D88537dF96569AE94a7F1A6E"),
		Collateral:                  common.HexToAddress("0x55d398326f99059fF775485246999027B3197955"), // USDT
		Conditional:                 common.HexToAddress("0x22DA1810B194ca018378464a58f6Ac2B10C9d244"),
		YieldBearingExchange:        common.HexToAddress("0x6bEb5a40C032AFc305961162d8204CDA16DECFa5"),
		YieldBearingNegRiskExchange: common.HexToAddress("0x8A289d458f5a134bA40015085A8F50Ffb681B41d"),
	}
)

func GetContracts(chainId int64) (*Contracts, error) {
	switch chainId {
	case 56:
		return _BNB_CHAIN_CONTRACTS, nil
	default:
		return nil, fmt.Errorf("invalid chain id: %d, only BNB Chain (56) is supported", chainId)
	}
}
