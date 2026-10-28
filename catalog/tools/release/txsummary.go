package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

var (
	txHashRe = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	hexQtyRe = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
)

// Receipt is the part of an eth_getTransactionReceipt result (cast send --json, cast receipt --json) used
// for the ledger.
type Receipt struct {
	TransactionHash   string `json:"transactionHash"`
	BlockNumber       string `json:"blockNumber"`
	From              string `json:"from"`
	To                string `json:"to"`
	Status            string `json:"status"`
	GasUsed           string `json:"gasUsed"`
	EffectiveGasPrice string `json:"effectiveGasPrice"`
}

func hexQty(s string) (*big.Int, error) {
	if !hexQtyRe.MatchString(s) {
		return nil, fmt.Errorf("not a hex quantity: %q", s)
	}
	v, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, fmt.Errorf("not a hex quantity: %q", s)
	}
	return v, nil
}

// FeeUnits is the fee in fee-token base units (6 decimals): Tempo prices gas in attodollars (1e-18 USD),
// so units = ceil(gasUsed * effectiveGasPrice / 1e12), as MAINNET_LEDGER.md records it.
func FeeUnits(gasUsed, price *big.Int) *big.Int {
	n := new(big.Int).Mul(gasUsed, price)
	d := big.NewInt(1_000_000_000_000)
	q, r := new(big.Int).QuoRem(n, d, new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

func formatUnits6(u *big.Int) string {
	s := u.String()
	for len(s) < 7 {
		s = "0" + s
	}
	return s[:len(s)-6] + "." + s[len(s)-6:]
}

// TxSummary turns a receipt into the onchain record of a release and a MAINNET_LEDGER.md row.
type TxSummary struct {
	Record OnchainRecord `json:"record"`
	Ledger string        `json:"ledger"`
}

// SummarizeTx checks a successful receipt and builds the record. The labels name the sender and target in
// the ledger (OPS, AppRegistry); purpose is the ledger's purpose column.
func SummarizeTx(d Defaults, raw []byte, chainID uint64, registry, releaseID, fromLabel, toLabel, purpose string, timestamp int64) (*TxSummary, error) {
	var r Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	r.TransactionHash = strings.ToLower(r.TransactionHash)
	if !txHashRe.MatchString(r.TransactionHash) {
		return nil, fmt.Errorf("receipt: bad transactionHash %q", r.TransactionHash)
	}
	if r.Status != "0x1" && r.Status != "1" {
		return nil, fmt.Errorf("receipt: transaction %s failed (status %s)", r.TransactionHash, r.Status)
	}
	block, err := hexQty(r.BlockNumber)
	if err != nil {
		return nil, fmt.Errorf("receipt: blockNumber: %w", err)
	}
	gas, err := hexQty(r.GasUsed)
	if err != nil {
		return nil, fmt.Errorf("receipt: gasUsed: %w", err)
	}
	price, err := hexQty(r.EffectiveGasPrice)
	if err != nil {
		return nil, fmt.Errorf("receipt: effectiveGasPrice: %w", err)
	}
	units := FeeUnits(gas, price)
	explorer := d.ExplorerURL + "/tx/" + r.TransactionHash
	rec := OnchainRecord{ChainID: chainID, AppRegistry: strings.ToLower(registry), TxHash: r.TransactionHash,
		BlockNumber: block.Uint64(), From: strings.ToLower(r.From), ReleaseID: strings.ToLower(releaseID),
		FeeUnits: units.String(), FeeUSD: formatUnits6(units), Explorer: explorer}
	when := "unknown"
	if timestamp > 0 {
		when = time.Unix(timestamp, 0).UTC().Format(time.DateTime)
	}
	ledger := fmt.Sprintf("| %s | %s %s | %s %s | %s | [%s…%s](%s) | %s | 0 |", when, fromLabel, r.From, toLabel, registry, purpose,
		r.TransactionHash[:10], r.TransactionHash[len(r.TransactionHash)-6:], explorer, rec.FeeUSD)
	return &TxSummary{Record: rec, Ledger: ledger}, nil
}
