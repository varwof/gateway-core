// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// databasePlugin enforces the std/database-v1 capability contract at the
// operation layer: the actual request (table / columns / limit, carried in
// HTTP query parameters by the structured data API) must stay within the
// parameter boundary declared in the AIC capability. Out-of-scope operations
// are denied (P2-A-06/A-07).
//
// The AIC capability parameters use the std/database-v1 params_schema:
//
//	{"tables":["customers","orders"],
//	 "columns":{"customers":["id","name"]},
//	 "limit":{"max":500}}
type databasePlugin struct {
	scheme string
}

func newDatabasePlugin(scheme string, cfg map[string]interface{}) (*databasePlugin, error) {
	return &databasePlugin{scheme: scheme}, nil
}

func (p *databasePlugin) Scheme() string { return p.scheme }

func (p *databasePlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if len(cap.Parameters) == 0 {
		return &PluginResult{Decision: PluginAllow,
			Reason: "database capability unconstrained (no parameter boundary)"}, nil
	}

	var bound struct {
		Tables  []string            `json:"tables"`
		Columns map[string][]string `json:"columns"`
		Limit   struct {
			Max int64 `json:"max"`
		} `json:"limit"`
	}
	if err := json.Unmarshal(cap.Parameters, &bound); err != nil {
		return &PluginResult{Decision: PluginDeny,
			Reason: "database capability parameters malformed"}, nil
	}

	table := ""
	if q := ctx.Query["table"]; len(q) > 0 {
		table = q[0]
	}
	var cols []string
	if q := ctx.Query["cols"]; len(q) > 0 {
		cols = splitCSV(q[0])
	}
	var limit int64
	if q := ctx.Query["limit"]; len(q) > 0 {
		limit, _ = strconv.ParseInt(q[0], 10, 64)
	}

	// Table must be within the authorized set.
	if len(bound.Tables) > 0 && !contains(bound.Tables, table) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("table %q not in authorized set %v", table, bound.Tables)}, nil
	}

	// Columns must be within the per-table allowlist (if declared).
	if allowed, declared := bound.Columns[table]; declared {
		if len(allowed) == 1 && allowed[0] == "*" {
			// wildcard: all columns
		} else if len(cols) > 0 {
			for _, c := range cols {
				if !contains(allowed, c) {
					return &PluginResult{Decision: PluginDeny,
						Reason: fmt.Sprintf("column %q not in authorized set %v", c, allowed)}, nil
				}
			}
		}
	}

	// Limit must not exceed the declared maximum.
	if bound.Limit.Max > 0 && limit > bound.Limit.Max {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("limit %d exceeds authorized maximum %d", limit, bound.Limit.Max)}, nil
	}

	return &PluginResult{Decision: PluginAllow,
		Reason: "operation within database capability boundary"}, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
