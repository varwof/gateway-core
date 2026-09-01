// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import "testing"

func TestDatabasePluginEnforcesParams(t *testing.T) {
	p, err := newDatabasePlugin("std/database-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	cap := &Capability{
		SchemeId:     "std/database-v1",
		CapabilityId: "query:SELECT",
		Parameters: []byte(`{"tables":["customers","orders"],
			"columns":{"customers":["id","name","email"]},
			"limit":{"max":500}}`),
	}

	cases := []struct {
		name  string
		query map[string][]string
		allow bool
	}{
		{"in scope", map[string][]string{"table": {"customers"}, "cols": {"id,name"}, "limit": {"100"}}, true},
		{"table out", map[string][]string{"table": {"secret_table"}, "cols": {"id"}}, false},
		{"column out", map[string][]string{"table": {"customers"}, "cols": {"id,password"}}, false},
		{"limit over", map[string][]string{"table": {"customers"}, "cols": {"id"}, "limit": {"999"}}, false},
		{"no params ok", map[string][]string{"table": {"customers"}}, true},
	}
	for _, c := range cases {
		res, err := p.Execute(cap, &PluginContext{Query: c.query})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := res.Decision == PluginAllow
		if got != c.allow {
			t.Errorf("%s: allow=%v want %v (reason=%s)", c.name, got, c.allow, res.Reason)
		}
	}

	// Unconstrained capability (no params) is allowed.
	noParams := &Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}
	res, err := p.Execute(noParams, &PluginContext{Query: map[string][]string{"table": {"anything"}}})
	if err != nil || res.Decision != PluginAllow {
		t.Fatalf("unconstrained should allow: %+v err=%v", res, err)
	}

	// Malformed params fail closed.
	bad := &Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{oops`)}
	res, err = p.Execute(bad, &PluginContext{})
	if err != nil || res.Decision != PluginDeny {
		t.Fatalf("malformed params should deny: %+v err=%v", res, err)
	}
}
