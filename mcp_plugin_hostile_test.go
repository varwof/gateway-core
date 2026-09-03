// SPDX-FileCopyrightText: 2026 EMILIA Protocol
// SPDX-License-Identifier: Apache-2.0

package gw

import "testing"

func TestMCPPluginHostileBoundaryCases(t *testing.T) {
	p, _ := newMCPPlugin("std/mcp-v1", nil)
	cap := &Capability{SchemeId: "std/mcp-v1", CapabilityId: "tools:call",
		Parameters: []byte(`{"tools":["read_file"],"tool_args":{"read_file":{"path_prefixes":["/workspace"]}}}`)}

	cases := []struct {
		name string
		body string
	}{
		{"lexical sibling", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace-evil/secret"}}}`},
		{"parent traversal", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/../etc/shadow"}}}`},
		{"missing tool name", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{"path":"/workspace/src/a.txt"}}}`},
	}
	for _, tc := range cases {
		res, err := p.Execute(cap, &PluginContext{Body: []byte(tc.body)})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Decision == PluginAllow {
			t.Errorf("%s unexpectedly allowed: %s", tc.name, res.Reason)
		}
	}

	emptyAllowlist := &Capability{SchemeId: "std/mcp-v1", CapabilityId: "tools:call",
		Parameters: []byte(`{"tools":[]}`)}
	res, err := p.Execute(emptyAllowlist, &PluginContext{Body: []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"id"}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == PluginAllow {
		t.Errorf("empty allowlist unexpectedly allowed arbitrary tool: %s", res.Reason)
	}
}
