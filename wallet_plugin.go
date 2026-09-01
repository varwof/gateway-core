// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// walletPlugin enforces the std/wallet-v1 capability contract at the
// operation layer: a wallet operation (asset / amount / recipient / network,
// carried in a structured JSON body or query parameters) must stay within the
// parameter boundary declared in the AIC capability. Transfers outside the
// per-transaction amount, the recipient allowlist, or the authorized
// assets/networks are denied.
type walletPlugin struct {
	scheme string
}

func newWalletPlugin(scheme string, cfg map[string]interface{}) (*walletPlugin, error) {
	return &walletPlugin{scheme: scheme}, nil
}

func (p *walletPlugin) Scheme() string { return p.scheme }

func (p *walletPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if len(cap.Parameters) == 0 {
		return &PluginResult{Decision: PluginAllow,
			Reason: "wallet capability unconstrained (no parameter boundary)"}, nil
	}

	var bound struct {
		Assets         []string `json:"assets"`
		Networks       []string `json:"networks"`
		MaxAmountPerTx float64  `json:"max_amount_per_tx"`
		MaxAmountDaily float64  `json:"max_amount_daily"`
		Recipients     []string `json:"recipients"`
	}
	if err := json.Unmarshal(cap.Parameters, &bound); err != nil {
		return &PluginResult{Decision: PluginDeny,
			Reason: "wallet capability parameters malformed"}, nil
	}

	op := walletOperationFromContext(ctx)

	if len(bound.Assets) > 0 && op.Asset != "" && !contains(bound.Assets, op.Asset) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("asset %q not in authorized set %v", op.Asset, bound.Assets)}, nil
	}
	if len(bound.Networks) > 0 && op.Network != "" && !contains(bound.Networks, op.Network) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("network %q not in authorized set %v", op.Network, bound.Networks)}, nil
	}

	switch cap.CapabilityId {
	case "transfer":
		if len(bound.Recipients) > 0 && op.Recipient != "" && !contains(bound.Recipients, op.Recipient) {
			return &PluginResult{Decision: PluginDeny,
				Reason: fmt.Sprintf("recipient %q not in allowlist %v", op.Recipient, bound.Recipients)}, nil
		}
		if bound.MaxAmountPerTx > 0 && op.Amount > bound.MaxAmountPerTx {
			return &PluginResult{Decision: PluginDeny,
				Reason: fmt.Sprintf("amount %g exceeds per-transaction maximum %g", op.Amount, bound.MaxAmountPerTx)}, nil
		}
		if bound.MaxAmountDaily > 0 && op.DailyTotal > bound.MaxAmountDaily {
			return &PluginResult{Decision: PluginDeny,
				Reason: fmt.Sprintf("daily total %g exceeds maximum %g", op.DailyTotal, bound.MaxAmountDaily)}, nil
		}
	}

	return &PluginResult{Decision: PluginAllow,
		Reason: "operation within wallet capability boundary"}, nil
}

type walletOperation struct {
	Asset      string
	Amount     float64
	Recipient  string
	Network    string
	DailyTotal float64
}

func walletOperationFromContext(ctx *PluginContext) walletOperation {
	var op walletOperation
	if len(ctx.Body) > 0 {
		var b struct {
			Asset      string  `json:"asset"`
			Amount     float64 `json:"amount"`
			Recipient  string  `json:"recipient"`
			Network    string  `json:"network"`
			DailyTotal float64 `json:"daily_total"`
		}
		if json.Unmarshal(ctx.Body, &b) == nil {
			op.Asset = b.Asset
			op.Amount = b.Amount
			op.Recipient = b.Recipient
			op.Network = b.Network
			op.DailyTotal = b.DailyTotal
			return op
		}
	}
	if q := ctx.Query["asset"]; len(q) > 0 {
		op.Asset = q[0]
	}
	if q := ctx.Query["amount"]; len(q) > 0 {
		op.Amount, _ = strconv.ParseFloat(q[0], 64)
	}
	if q := ctx.Query["recipient"]; len(q) > 0 {
		op.Recipient = q[0]
	}
	if q := ctx.Query["network"]; len(q) > 0 {
		op.Network = q[0]
	}
	if q := ctx.Query["daily_total"]; len(q) > 0 {
		op.DailyTotal, _ = strconv.ParseFloat(q[0], 64)
	}
	return op
}
