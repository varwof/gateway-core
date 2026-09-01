// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
)

// mcpPlugin enforces the std/mcp-v1 capability contract at the operation
// layer: an MCP tools/call must reference a tool in the AIC-declared
// allowlist. Other JSON-RPC methods (initialize/ping/tools/list) are allowed
// as read-only protocol.
type mcpPlugin struct {
	scheme string
}

func newMCPPlugin(scheme string, cfg map[string]interface{}) (*mcpPlugin, error) {
	return &mcpPlugin{scheme: scheme}, nil
}

func (p *mcpPlugin) Scheme() string { return p.scheme }

func (p *mcpPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if len(cap.Parameters) == 0 {
		return &PluginResult{Decision: PluginAllow,
			Reason: "mcp capability unconstrained (no tool allowlist)"}, nil
	}
	var bound struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(cap.Parameters, &bound); err != nil {
		return &PluginResult{Decision: PluginDeny,
			Reason: "mcp capability parameters malformed"}, nil
	}

	// Only tools/call is capability-scoped; protocol methods pass.
	if len(ctx.Body) == 0 {
		return &PluginResult{Decision: PluginAllow,
			Reason: "no JSON-RPC body (protocol method)"}, nil
	}
	var rpc struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(ctx.Body, &rpc); err != nil {
		return &PluginResult{Decision: PluginDeny,
			Reason: "malformed JSON-RPC body"}, nil
	}
	if rpc.Method != "tools/call" {
		return &PluginResult{Decision: PluginAllow,
			Reason: fmt.Sprintf("protocol method %q (read-only)", rpc.Method)}, nil
	}
	if len(bound.Tools) > 0 && rpc.Params.Name != "" && !contains(bound.Tools, rpc.Params.Name) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("tool %q not in allowlist %v", rpc.Params.Name, bound.Tools)}, nil
	}
	return &PluginResult{Decision: PluginAllow,
		Reason: "tool call within mcp capability boundary"}, nil
}
