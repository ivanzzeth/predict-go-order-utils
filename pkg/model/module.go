package model

type VerifyingContract = int

const (
	CTFExchange VerifyingContract = iota
	NegRiskCTFExchange
	YieldBearingCTFExchange
	YieldBearingNegRiskCTFExchange
)
