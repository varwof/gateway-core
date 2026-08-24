// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509"
	"testing"
)

type recordingPlugin struct {
	got *PluginContext
}

func (p *recordingPlugin) Scheme() string { return "http" }

func (p *recordingPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	p.got = ctx
	return &PluginResult{Decision: PluginAllow, Reason: "ok"}, nil
}

// TestPipelineHTTPFactsReachPlugin verifies that HTTP facts configured
// on PipelineConfig are copied into the PluginContext of capability
// plugins.
func TestPipelineHTTPFactsReachPlugin(t *testing.T) {
	cert := makeAICCertWithConstraints(t, nil) // capability http:gateway:read
	rec := &recordingPlugin{}
	reg := NewPluginRegistry()
	if err := reg.Register(rec); err != nil {
		t.Fatal(err)
	}
	facts := &HTTPFacts{
		Method:  "GET",
		Path:    "/api/tables/customers/rows",
		Query:   map[string][]string{"tenant": {"org-a"}},
		Headers: map[string]string{"x-role": "readonly"},
	}
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
		CapabilityPluginRegistry: reg,
		HTTPFacts:                facts,
	})
	if !r.Granted {
		t.Fatalf("expected granted: %s", r.DenyReason)
	}
	if rec.got == nil {
		t.Fatal("plugin was not called")
	}
	if rec.got.Method != "GET" || rec.got.Path != "/api/tables/customers/rows" {
		t.Fatalf("HTTP facts not delivered: %+v", rec.got)
	}
	if len(rec.got.Query) != 1 || rec.got.Query["tenant"][0] != "org-a" {
		t.Fatalf("query not delivered: %+v", rec.got.Query)
	}
	if rec.got.Headers["x-role"] != "readonly" {
		t.Fatalf("headers not delivered: %+v", rec.got.Headers)
	}
}
