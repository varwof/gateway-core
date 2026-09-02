// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import "testing"

func TestDeployPluginEnforcesParams(t *testing.T) {
	p, _ := newDeployPlugin("std/deploy-v1", nil)
	cap := &Capability{SchemeId: "std/deploy-v1", CapabilityId: "deploy:apply",
		Parameters: []byte(`{"environments":["staging","dev"],"namespaces":["web"],
			"resources":["deployment"],"max_replicas":5}`)}
	cases := []struct {
		name  string
		body  string
		allow bool
	}{
		{"staging ok", `{"environment":"staging","namespace":"web","resource":"deployment","replicas":3}`, true},
		{"prod denied", `{"environment":"production","namespace":"web","replicas":3}`, false},
		{"namespace out", `{"environment":"staging","namespace":"billing","replicas":3}`, false},
		{"replicas over", `{"environment":"staging","namespace":"web","replicas":9}`, false},
	}
	for _, c := range cases {
		res, err := p.Execute(cap, &PluginContext{Body: []byte(c.body)})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (res.Decision == PluginAllow) != c.allow {
			t.Errorf("%s: allow=%v want %v (reason=%s)", c.name, res.Decision == PluginAllow, c.allow, res.Reason)
		}
	}

	// secret:read allowlist.
	scap := &Capability{SchemeId: "std/deploy-v1", CapabilityId: "secret:read",
		Parameters: []byte(`{"secrets":["api-key-staging"]}`)}
	sres, _ := p.Execute(scap, &PluginContext{Query: map[string][]string{"secret": {"api-key-staging"}}})
	if sres.Decision != PluginAllow {
		t.Fatalf("allowlisted secret: %+v", sres)
	}
	sres, _ = p.Execute(scap, &PluginContext{Query: map[string][]string{"secret": {"db-root"}}})
	if sres.Decision != PluginDeny {
		t.Fatalf("non-allowlisted secret must deny: %+v", sres)
	}
}

func TestMCPPluginEnforcesToolAllowlist(t *testing.T) {
	p, _ := newMCPPlugin("std/mcp-v1", nil)
	cap := &Capability{SchemeId: "std/mcp-v1", CapabilityId: "tools:call",
		Parameters: []byte(`{"tools":["read_file","list_dir"]}`)}

	ok := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/a"}}}`
	res, err := p.Execute(cap, &PluginContext{Body: []byte(ok)})
	if err != nil || res.Decision != PluginAllow {
		t.Fatalf("allowlisted tool: %+v err=%v", res, err)
	}

	deny := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"rm -rf /"}}}`
	res, err = p.Execute(cap, &PluginContext{Body: []byte(deny)})
	if err != nil || res.Decision != PluginDeny {
		t.Fatalf("bash tool must deny: %+v err=%v", res, err)
	}

	// Protocol methods pass.
	proto := `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}`
	res, err = p.Execute(cap, &PluginContext{Body: []byte(proto)})
	if err != nil || res.Decision != PluginAllow {
		t.Fatalf("protocol method should pass: %+v err=%v", res, err)
	}
}

func TestMCPPluginArgumentSubset(t *testing.T) {
	// Predicate 2: allowlisted tool + argument bounds. read_file is allowed,
	// but only under the certificate-bound path prefixes.
	p, _ := newMCPPlugin("std/mcp-v1", nil)
	cap := &Capability{SchemeId: "std/mcp-v1", CapabilityId: "tools:call",
		Parameters: []byte(`{"tools":["read_file","list_dir"],
			"tool_args":{"read_file":{"path_prefixes":["/workspace"]}}}`)}

	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/src/a.txt"}}}`
	res, err := p.Execute(cap, &PluginContext{Body: []byte(in)})
	if err != nil || res.Decision != PluginAllow {
		t.Fatalf("path under prefix should allow: %+v err=%v", res, err)
	}

	out := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}`
	res, err = p.Execute(cap, &PluginContext{Body: []byte(out)})
	if err != nil || res.Decision != PluginDeny {
		t.Fatalf("path outside prefix must deny: %+v err=%v", res, err)
	}

	missing := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	res, err = p.Execute(cap, &PluginContext{Body: []byte(missing)})
	if err != nil || res.Decision != PluginDeny {
		t.Fatalf("missing path with prefix bound must deny: %+v err=%v", res, err)
	}

	// Tool without per-tool args stays allowlist-only (class grant).
	nobound := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_dir","arguments":{"path":"/etc"}}}`
	res, err = p.Execute(cap, &PluginContext{Body: []byte(nobound)})
	if err != nil || res.Decision != PluginAllow {
		t.Fatalf("list_dir (no arg bounds) should allow: %+v err=%v", res, err)
	}
}
