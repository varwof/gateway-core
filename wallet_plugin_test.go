// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import "testing"

func TestWalletPluginEnforcesParams(t *testing.T) {
	p, _ := newWalletPlugin("std/wallet-v1", nil)
	cap := &Capability{
		SchemeId:     "std/wallet-v1",
		CapabilityId: "transfer",
		Parameters: []byte(`{"assets":["USDC","USDT"],"networks":["ethereum"],
			"max_amount_per_tx":100,"recipients":["0xVendor","0xPartner"]}`),
	}

	cases := []struct {
		name  string
		body  string
		allow bool
	}{
		{"in scope", `{"asset":"USDC","amount":50,"recipient":"0xVendor","network":"ethereum"}`, true},
		{"asset out", `{"asset":"BTC","amount":50,"recipient":"0xVendor"}`, false},
		{"amount over", `{"asset":"USDC","amount":150,"recipient":"0xVendor"}`, false},
		{"recipient out", `{"asset":"USDC","amount":50,"recipient":"0xStranger"}`, false},
		{"network out", `{"asset":"USDC","amount":50,"recipient":"0xVendor","network":"solana"}`, false},
	}
	for _, c := range cases {
		res, err := p.Execute(cap, &PluginContext{Body: []byte(c.body)})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := res.Decision == PluginAllow
		if got != c.allow {
			t.Errorf("%s: allow=%v want %v (reason=%s)", c.name, got, c.allow, res.Reason)
		}
	}

	// balance cap: asset scope only.
	bcap := &Capability{SchemeId: "std/wallet-v1", CapabilityId: "balance",
		Parameters: []byte(`{"assets":["USDC"]}`)}
	bres, err := p.Execute(bcap, &PluginContext{Query: map[string][]string{"asset": {"USDC"}}})
	if err != nil || bres.Decision != PluginAllow {
		t.Fatalf("balance in scope: %+v err=%v", bres, err)
	}
	bres, err = p.Execute(bcap, &PluginContext{Query: map[string][]string{"asset": {"BTC"}}})
	if err != nil || bres.Decision != PluginDeny {
		t.Fatalf("balance out of scope: %+v err=%v", bres, err)
	}
}
