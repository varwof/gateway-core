// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
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
		Tools    *[]string `json:"tools"`
		ToolArgs map[string]struct {
			PathPrefixes []string `json:"path_prefixes"`
		} `json:"tool_args"`
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
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
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
	if rpc.Params.Name == "" {
		return &PluginResult{Decision: PluginDeny,
			Reason: "tools/call missing params.name"}, nil
	}
	if bound.Tools != nil && !contains(*bound.Tools, rpc.Params.Name) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("tool %q not in allowlist %v", rpc.Params.Name, *bound.Tools)}, nil
	}
	// Field-level (argument) constraints, e.g. path_prefixes for read_file:
	// the tool is allowlisted, but its arguments must stay within the
	// certificate-bound bounds too (predicate 2, distinct from tool identity).
	if ta, ok := bound.ToolArgs[rpc.Params.Name]; ok && len(ta.PathPrefixes) > 0 {
		path, _ := rpc.Params.Arguments["path"].(string)
		if path == "" || !hasAnyPathPrefix(path, ta.PathPrefixes) {
			return &PluginResult{Decision: PluginDeny,
				Reason: fmt.Sprintf("argument path %q outside allowed prefixes %v",
					path, ta.PathPrefixes)}, nil
		}
	}
	return &PluginResult{Decision: PluginAllow,
		Reason: "tool call within mcp capability boundary"}, nil
}

func hasAnyPathPrefix(s string, prefixes []string) bool {
	cleanedPath := path.Clean(s)
	for _, pre := range prefixes {
		if pre == "" {
			continue
		}
		cleanedPrefix := path.Clean(pre)
		if cleanedPrefix == "/" && strings.HasPrefix(cleanedPath, "/") {
			return true
		}
		if cleanedPath == cleanedPrefix || strings.HasPrefix(cleanedPath, cleanedPrefix+"/") {
			return true
		}
	}
	return false
}
