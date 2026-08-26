// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"
	"time"
)

func constrCap(id string, params string) Capability {
	return Capability{SchemeId: "constraint", CapabilityId: id, Parameters: []byte(params)}
}

func cidrCap(params string) Capability { return constrCap(ConstraintCIDRKey, params) }

func timeWindowCap(params string) Capability { return constrCap(ConstraintTimeWindowKey, params) }

func geoFenceCap(params string) Capability { return constrCap(ConstraintGeoFenceKey, params) }

// makeAICCertWithConstraints constructs an AIC certificate carrying authorizationConstraints.
func makeAICCertWithConstraints(t *testing.T, constraints []Capability) *x509.Certificate {
	t.Helper()
	aic := AIC{
		AgentId:                  "agent-constraint",
		PrincipalUid:             PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities:             []Capability{{SchemeId: "http", CapabilityId: "gateway:read"}},
		AuthorizationConstraints: constraints,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	return makeCertWithExt(t, oidAIC, aicVal)
}

func TestConstraintRegistry_RegisterFindRemove(t *testing.T) {
	r := NewConstraintRegistry()
	if r.Len() != 0 {
		t.Fatalf("new registry Len() = %d, want 0", r.Len())
	}
	ev := cidrEvaluator{}
	if err := r.Register(ev); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.Register(ev); err == nil {
		t.Fatal("duplicate Register should fail")
	}
	got, err := r.Find(ConstraintCIDRKey)
	if err != nil || got != ev {
		t.Fatalf("Find = %v, %v; want %v, nil", got, err, ev)
	}
	if _, err := r.Find("nope"); err == nil {
		t.Fatal("Find unknown should fail")
	}
	r.Remove(ConstraintCIDRKey)
	if _, err := r.Find(ConstraintCIDRKey); err == nil {
		t.Fatal("Find after Remove should fail")
	}
	r.Register(ev)
	keys := r.Keys()
	if len(keys) != 1 || keys[0] != ConstraintCIDRKey {
		t.Fatalf("Keys = %v", keys)
	}
}

func TestConstraintRegistry_ReplaceAndNil(t *testing.T) {
	r := NewConstraintRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatal("Register nil should fail")
	}
	if err := r.Replace(nil); err == nil {
		t.Fatal("Replace nil should fail")
	}
	ev := cidrEvaluator{}
	ev2 := geoFenceEvaluator{}
	if err := r.Replace(ev); err != nil {
		t.Fatalf("Replace new: %v", err)
	}
	if err := r.Replace(ev2); err != nil {
		t.Fatalf("Replace existing: %v", err)
	}
	got, _ := r.Find(ConstraintGeoFenceKey)
	if got != ev2 {
		t.Fatalf("Replace did not take effect")
	}
}

func TestConstraintRegistry_Reset(t *testing.T) {
	r := NewConstraintRegistry()
	r.Register(cidrEvaluator{})
	r.Register(timeWindowEvaluator{})
	r.Reset()
	if r.Len() != 0 {
		t.Fatalf("Reset Len() = %d, want 0", r.Len())
	}
}

func TestResetConstraints_Builtin(t *testing.T) {
	ResetConstraints()
	for _, id := range []string{
		ConstraintCIDRKey, ConstraintTimeWindowKey, ConstraintConcurrentKey,
		ConstraintHardTimeoutKey, ConstraintIdleTimeoutKey,
		ConstraintReadOnlyKey, ConstraintAuditRequiredKey,
		ConstraintGeoFenceKey,
	} {
		if _, err := globalConstraintRegistry.Find(id); err != nil {
			t.Fatalf("builtin %q missing after ResetConstraints: %v", id, err)
		}
	}
	if globalConstraintRegistry.Len() != 8 {
		t.Fatalf("Len() = %d, want 8", globalConstraintRegistry.Len())
	}
}

func TestRegisterConstraint_Extension(t *testing.T) {
	ResetConstraints()
	ev := &countingEvaluator{capabilityId: "my-custom-constraint"}
	if err := RegisterConstraint(ev); err != nil {
		t.Fatalf("RegisterConstraint: %v", err)
	}
	if !isKnownConstraintType("my-custom-constraint") {
		t.Fatal("custom constraint should be known after register")
	}
	err := checkConstraintsAt([]Capability{constrCap("my-custom-constraint", `{}`)}, "", time.Now().In(time.UTC))
	if err != nil {
		t.Fatalf("custom constraint eval: %v", err)
	}
	if ev.calls != 1 {
		t.Fatalf("custom evaluator calls = %d, want 1", ev.calls)
	}
	ResetConstraints()
	if isKnownConstraintType("my-custom-constraint") {
		t.Fatal("custom constraint should be gone after ResetConstraints")
	}
}

type countingEvaluator struct {
	capabilityId string
	calls        int
}

func (e *countingEvaluator) CapabilityId() string { return e.capabilityId }

func (e *countingEvaluator) Evaluate(_ *Capability, _ *ConstraintContext) error {
	e.calls++
	return nil
}

func TestCheckAuthorizationConstraints_CIDR(t *testing.T) {
	cases := []struct {
		name     string
		cap      Capability
		clientIP string
		wantErr  bool
	}{
		{"array hit", cidrCap(`["10.0.0.0/8","172.16.0.0/12"]`), "10.1.2.3", false},
		{"array miss", cidrCap(`["10.0.0.0/8"]`), "192.168.1.1", true},
		{"array first of two", cidrCap(`["10.0.0.0/8","172.16.0.0/12"]`), "172.16.5.5", false},
		{"object hit", cidrCap(`{"cidrs":["10.0.0.0/8","172.16.0.0/12"]}`), "10.1.2.3", false},
		{"object miss", cidrCap(`{"cidrs":["10.0.0.0/8"]}`), "192.168.1.1", true},
		{"no client ip skip", cidrCap(`["10.0.0.0/8"]`), "", false},
		{"empty cidrs skip", cidrCap(`[]`), "192.168.1.1", false},
		{"invalid cidr", cidrCap(`["not-a-cidr"]`), "10.1.2.3", true},
		{"invalid json", cidrCap(`{`), "10.1.2.3", true},
		{"invalid ip", cidrCap(`["10.0.0.0/8"]`), "nope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAuthorizationConstraints([]Capability{tc.cap}, tc.clientIP)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckAuthorizationConstraints_SchemeFilter(t *testing.T) {
	err := CheckAuthorizationConstraints([]Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "allowed-cidr", Parameters: []byte(`["10.0.0.0/8"]`)}}, "192.168.1.1")
	if err != nil {
		t.Fatalf("non-constraint scheme should be skipped, got %v", err)
	}
}

func TestCheckAuthorizationConstraints_TimeWindow(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		params  string
		now     time.Time
		wantErr bool
	}{
		{"in window", `{"start":"09:00","end":"18:00"}`, time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC), false},
		{"before start", `{"start":"09:00","end":"18:00"}`, time.Date(2026, 8, 7, 8, 59, 0, 0, time.UTC), true},
		{"at start inclusive", `{"start":"09:00","end":"18:00"}`, time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC), false},
		{"at end exclusive", `{"start":"09:00","end":"18:00"}`, time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC), true},
		{"overnight in", `{"start":"22:00","end":"06:00"}`, time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC), false},
		{"overnight out", `{"start":"22:00","end":"06:00"}`, time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC), true},
		{"missing fields", `{"start":"09:00"}`, now, true},
		{"bad format", `{"start":"9:00","end":"18:00"}`, now, true},
		{"invalid json", `{`, now, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &ConstraintContext{ClientIP: "", Now: tc.now}
			err := checkConstraintsAt([]Capability{timeWindowCap(tc.params)}, ctx.ClientIP, ctx.Now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckAuthorizationConstraints_TimeWindowTZ(t *testing.T) {
	if _, err := time.LoadLocation("Asia/Shanghai"); err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	// Asia/Shanghai = UTC+8. Window 09:00-18:00 (Shanghai time).
	// UTC 01:00 = Shanghai 09:00 (window start, inclusive); UTC 09:59 = Shanghai 17:59 (within window); UTC 10:00 = Shanghai 18:00 (window end, exclusive).
	cases := []struct {
		name    string
		hhmm    string
		wantErr bool
	}{
		{"cn morning in", "01:00", false},
		{"cn afternoon in", "09:59", false},
		{"cn opening boundary in", "01:30", false},
		{"cn before open", "00:59", true},
		{"cn closing boundary out", "10:00", true},
	}
	cap := timeWindowCap(`{"start":"09:00","end":"18:00","tz":"Asia/Shanghai"}`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAuthorizationConstraintsAt([]Capability{cap}, "", tc.hhmm)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckAuthorizationConstraints_TimeWindowInvalidTZ(t *testing.T) {
	cap := timeWindowCap(`{"start":"09:00","end":"18:00","tz":"Mars/Olympus"}`)
	err := CheckAuthorizationConstraints([]Capability{cap}, "")
	if err == nil || !strings.Contains(err.Error(), "invalid tz") {
		t.Fatalf("err = %v, want invalid tz error", err)
	}
}

func TestCheckAuthorizationConstraints_GeoFence_Inline(t *testing.T) {
	cap := geoFenceCap(`{"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8","192.168.0.0/16"],"CN-BJS":["172.16.0.0/12"]}}`)
	cases := []struct {
		name     string
		clientIP string
		wantErr  bool
	}{
		{"region A hit", "10.0.0.1", false},
		{"region A second cidr", "192.168.10.1", false},
		{"region B hit", "172.16.5.5", false},
		{"miss", "203.0.113.7", true},
		{"no client ip skip", "", false},
		{"invalid ip", "nope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAuthorizationConstraints([]Capability{cap}, tc.clientIP)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckAuthorizationConstraints_GeoFence_DefaultInline(t *testing.T) {
	// Default resolver is treated as inline.
	cap := geoFenceCap(`{"regions":{"CN-SHA":["10.0.0.0/8"]}}`)
	if err := CheckAuthorizationConstraints([]Capability{cap}, "10.1.1.1"); err != nil {
		t.Fatalf("default inline should hit: %v", err)
	}
	if err := CheckAuthorizationConstraints([]Capability{cap}, "203.0.113.1"); err == nil {
		t.Fatal("should miss")
	}
}

func TestCheckAuthorizationConstraints_GeoFence_BadTable(t *testing.T) {
	cap := geoFenceCap(`{"regions":{"CN-SHA":"not-a-list"}}`)
	if err := CheckAuthorizationConstraints([]Capability{cap}, "10.1.1.1"); err == nil {
		t.Fatal("bad inline table should fail")
	}
	cap = geoFenceCap(`{"regions":{"CN-SHA":["not-a-cidr"]}}`)
	if err := CheckAuthorizationConstraints([]Capability{cap}, "10.1.1.1"); err == nil {
		t.Fatal("bad cidr should fail")
	}
}

func TestCheckAuthorizationConstraints_GeoFence_Resolver(t *testing.T) {
	name := fmt.Sprintf("test-geo-%d", time.Now().UnixNano())
	defer func() { delete(geoResolvers, name) }()

	// Unregistered resolver: must fail (deny), not silently allow.
	unreg := geoFenceCap(`{"resolver":"` + name + `","regions":["CN-SHA"]}`)
	if err := CheckAuthorizationConstraints([]Capability{unreg}, "203.0.113.5"); err == nil {
		t.Fatal("unregistered resolver should fail closed")
	}

	RegisterGeoResolver(name, func(ip string) (string, error) {
		if ip == "203.0.113.5" {
			return "CN-SHA", nil
		}
		return "", fmt.Errorf("unknown ip %s", ip)
	})
	if err := CheckAuthorizationConstraints([]Capability{unreg}, "203.0.113.5"); err != nil {
		t.Fatalf("registered resolver hit: %v", err)
	}
	miss := geoFenceCap(`{"resolver":"` + name + `","regions":["CN-BJS"]}`)
	if err := CheckAuthorizationConstraints([]Capability{miss}, "203.0.113.5"); err == nil {
		t.Fatal("resolver result not in allowed regions should fail")
	}
}

func TestCheckAuthorizationConstraints_UnknownIgnored(t *testing.T) {
	cap := constrCap("brand-new-constraint", `{}`)
	if err := CheckAuthorizationConstraints([]Capability{cap}, "10.1.1.1"); err != nil {
		t.Fatalf("unknown constraint should be ignored, got %v", err)
	}
}

func TestIsKnownConstraintType(t *testing.T) {
	ResetConstraints()
	for _, id := range []string{
		ConstraintCIDRKey, ConstraintTimeWindowKey, ConstraintConcurrentKey,
		ConstraintHardTimeoutKey, ConstraintIdleTimeoutKey,
		ConstraintReadOnlyKey, ConstraintAuditRequiredKey,
		ConstraintGeoFenceKey,
	} {
		if !isKnownConstraintType(id) {
			t.Fatalf("%q should be known", id)
		}
	}
	if isKnownConstraintType("whatever") {
		t.Fatal("unknown type should not be known")
	}
	ResetConstraints()
}

func TestMaxConcurrentEvaluator(t *testing.T) {
	ResetConstraints()
	ev, err := globalConstraintRegistry.Find(ConstraintConcurrentKey)
	if err != nil {
		t.Fatalf("max-concurrent not registered: %v", err)
	}
	ctx := &ConstraintContext{}
	// Valid {"max":10} -> pass.
	if err := ev.Evaluate(&Capability{Parameters: []byte(`{"max": 10}`)}, ctx); err != nil {
		t.Fatalf("valid max-concurrent rejected: %v", err)
	}
	// Empty params -> pass (not configured).
	if err := ev.Evaluate(&Capability{}, ctx); err != nil {
		t.Fatalf("empty params rejected: %v", err)
	}
	// Boundary 1 / 1024 -> pass.
	for _, m := range []int{1, 1024} {
		if err := ev.Evaluate(&Capability{Parameters: []byte(fmt.Sprintf(`{"max": %d}`, m))}, ctx); err != nil {
			t.Fatalf("boundary max=%d rejected: %v", m, err)
		}
	}
	// Out of range 0 / 1025 -> deny.
	for _, m := range []int{0, 1025} {
		if err := ev.Evaluate(&Capability{Parameters: []byte(fmt.Sprintf(`{"max": %d}`, m))}, ctx); err == nil {
			t.Fatalf("max=%d should be rejected", m)
		}
	}
	// Non-JSON -> deny.
	if err := ev.Evaluate(&Capability{Parameters: []byte(`{"max": "ten"}`)}, ctx); err == nil {
		t.Fatal("invalid max-concurrent JSON should be rejected")
	}
	ResetConstraints()
}

func TestCheckAdmission_ConstraintIntegration(t *testing.T) {
	cert := makeAICCertWithConstraints(t, []Capability{cidrCap(`["10.0.0.0/8"]`)})
	res := CheckAdmission(cert, AdmissionConfig{RequireAIC: true, EnforceConstraints: true, ClientIP: "10.1.2.3"})
	if res.Decision != DecisionAllow {
		t.Fatalf("in-cidr admission = %v (%s), want allow", res.Decision, res.Reason)
	}
	res = CheckAdmission(cert, AdmissionConfig{RequireAIC: true, EnforceConstraints: true, ClientIP: "192.168.1.1"})
	if res.Decision != DecisionDeny {
		t.Fatalf("out-of-cidr admission = %v, want deny", res.Decision)
	}
}

func TestCheckAdmission_GeoFenceIntegration(t *testing.T) {
	cert := makeAICCertWithConstraints(t, []Capability{geoFenceCap(`{"regions":{"CN-SHA":["10.0.0.0/8"]}}`)})
	res := CheckAdmission(cert, AdmissionConfig{RequireAIC: true, EnforceConstraints: true, ClientIP: "10.1.2.3"})
	if res.Decision != DecisionAllow {
		t.Fatalf("geo hit admission = %v (%s), want allow", res.Decision, res.Reason)
	}
	res = CheckAdmission(cert, AdmissionConfig{RequireAIC: true, EnforceConstraints: true, ClientIP: "203.0.113.7"})
	if res.Decision != DecisionDeny {
		t.Fatalf("geo miss admission = %v, want deny", res.Decision)
	}
}

func TestCheckAdmission_UnknownConstraintIgnored(t *testing.T) {
	cert := makeAICCertWithConstraints(t, []Capability{constrCap("brand-new-constraint", `{}`)})
	res := CheckAdmission(cert, AdmissionConfig{RequireAIC: true, EnforceConstraints: true, ClientIP: "10.1.2.3"})
	if res.Decision != DecisionAllow {
		t.Fatalf("unknown constraint should be ignored in admission, got %v (%s)", res.Decision, res.Reason)
	}
}

// TestCheckAdmission_StrictConstraints_Deny strict mode: unknown constraint fail-closed (spec P1-B-23).
func TestCheckAdmission_StrictConstraints_Deny(t *testing.T) {
	cert := makeAICCertWithConstraints(t, []Capability{constrCap("brand-new-constraint", `{}`)})
	res := CheckAdmission(cert, AdmissionConfig{
		RequireAIC:         true,
		EnforceConstraints: true,
		StrictConstraints:  true,
		ClientIP:           "10.1.2.3",
	})
	if res.Decision != DecisionDeny {
		t.Fatalf("strict mode should deny unknown constraint, got %v (%s)", res.Decision, res.Reason)
	}
	if !strings.Contains(res.Reason, "unknown constraint type") {
		t.Fatalf("deny reason should mention unknown constraint type, got %q", res.Reason)
	}
}

// TestCheckAdmission_StrictConstraints_Allow strict mode + all known constraints -> allow.
func TestCheckAdmission_StrictConstraints_Allow(t *testing.T) {
	cert := makeAICCertWithConstraints(t, []Capability{constrCap(ConstraintCIDRKey, `{}`)})
	res := CheckAdmission(cert, AdmissionConfig{
		RequireAIC:         true,
		EnforceConstraints: true,
		StrictConstraints:  true,
		ClientIP:           "10.1.2.3",
	})
	if res.Decision != DecisionAllow {
		t.Fatalf("known constraints in strict mode should Allow, got %v (%s)", res.Decision, res.Reason)
	}
}

// TestFirstUnknownConstraint helper behavior.
func TestFirstUnknownConstraint(t *testing.T) {
	if u := firstUnknownConstraint(nil); u != nil {
		t.Fatalf("nil constraints: want nil, got %+v", u)
	}
	if u := firstUnknownConstraint([]Capability{{SchemeId: "http", CapabilityId: "gateway:read"}}); u != nil {
		t.Fatalf("non-constraint scheme should be skipped, got %+v", u)
	}
	if u := firstUnknownConstraint([]Capability{{SchemeId: "constraint", CapabilityId: ConstraintCIDRKey}}); u != nil {
		t.Fatalf("known constraint should return nil, got %+v", u)
	}
	u := firstUnknownConstraint([]Capability{{SchemeId: "constraint-v1", CapabilityId: "nope"}})
	if u == nil || u.CapabilityId != "nope" {
		t.Fatalf("expected unknown constraint nope, got %+v", u)
	}
}

func TestCheckAdmission_TimeWindowTZIntegration(t *testing.T) {
	if _, err := time.LoadLocation("Asia/Shanghai"); err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	// Window 09:00-18:00 Asia/Shanghai (UTC+8). UTC 01:00 = Shanghai 09:00 within window.
	cap := timeWindowCap(`{"start":"09:00","end":"18:00","tz":"Asia/Shanghai"}`)
	if err := CheckAuthorizationConstraintsAt([]Capability{cap}, "", "01:00"); err != nil {
		t.Fatalf("UTC 01:00 should be in Asia/Shanghai window: %v", err)
	}
	if err := CheckAuthorizationConstraintsAt([]Capability{cap}, "", "10:00"); err == nil {
		t.Fatal("UTC 10:00 (= Shanghai 18:00, outside window) should fail")
	}
	// CheckAdmission integration (deterministic deny): window with start == end is never satisfied.
	empty := timeWindowCap(`{"start":"12:00","end":"12:00"}`)
	cert := makeAICCertWithConstraints(t, []Capability{empty})
	res := CheckAdmission(cert, AdmissionConfig{RequireAIC: true, EnforceConstraints: true, ClientIP: ""})
	if res.Decision != DecisionDeny {
		t.Fatalf("empty window admission = %v (%s), want deny", res.Decision, res.Reason)
	}
}

func TestGeoFenceE2EJSON(t *testing.T) {
	// Patent embodiment 6 local policy JSON format (authorizationConstraints encoded in cert) should be parseable.
	cap := Capability{
		SchemeId:     "constraint-v1",
		CapabilityId: "geo-fence",
		Parameters: []byte(`{
			"resolver": "inline",
			"regions": {"CN-SHA": ["10.0.0.0/8", "172.16.0.0/12"], "CN-BJS": ["192.168.0.0/16"]}
		}`),
	}
	if err := CheckAuthorizationConstraints([]Capability{cap}, "10.10.10.10"); err != nil {
		t.Fatalf("embodiment JSON hit: %v", err)
	}
	if err := CheckAuthorizationConstraints([]Capability{cap}, "203.0.113.9"); err == nil {
		t.Fatal("embodiment JSON miss should fail")
	}
}

func TestParseCIDRParamFormats(t *testing.T) {
	if _, err := parseCIDRParam([]byte(`["10.0.0.0/8"]`)); err != nil {
		t.Fatalf("array: %v", err)
	}
	if _, err := parseCIDRParam([]byte(`{"cidrs":["10.0.0.0/8"]}`)); err != nil {
		t.Fatalf("object: %v", err)
	}
	if _, err := parseCIDRParam([]byte(`{"wrong":"x"}`)); err != nil {
		t.Fatalf("empty object ok: %v", err)
	}
	if _, err := parseCIDRParam(nil); err == nil {
		t.Fatal("nil should fail (matches legacy behavior)")
	}
}

// TestConstraintRecheckLoopViolation G3: periodic recheck triggers onViolation and stops loop
// when constraint has become invalid (time-window start==end never matches).
func TestConstraintRecheckLoopViolation(t *testing.T) {
	cons := []Capability{timeWindowCap(`{"start":"23:59","end":"23:59"}`)}
	done := make(chan struct{})
	violated := make(chan string, 1)
	go ConstraintRecheckLoop(cons, nil, "", 20*time.Millisecond, done, func(reason string) {
		select {
		case violated <- reason:
		default:
		}
	})
	select {
	case reason := <-violated:
		if !strings.Contains(reason, "time-window") {
			t.Fatalf("expected time-window violation, got %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected constraint violation, loop never fired")
	}
	close(done)
}

// TestConstraintRecheckLoopNoViolation G3: when constraint remains satisfied (window never expires),
// loop runs until done is closed without triggering onViolation.
func TestConstraintRecheckLoopNoViolation(t *testing.T) {
	// All-day window never expires.
	cons := []Capability{timeWindowCap(`{"start":"00:00","end":"23:59"}`)}
	done := make(chan struct{})
	violated := make(chan string, 1)
	go ConstraintRecheckLoop(cons, nil, "", 20*time.Millisecond, done, func(reason string) {
		select {
		case violated <- reason:
		default:
		}
	})
	time.Sleep(150 * time.Millisecond)
	select {
	case r := <-violated:
		t.Fatalf("unexpected violation: %q", r)
	default:
	}
	close(done)
}

// TestConstraintRecheckLoopStopsOnDone G3: done close stops immediately, even if constraint
// has expired, onViolation is not triggered (idempotent stop).
func TestConstraintRecheckLoopStopsOnDone(t *testing.T) {
	cons := []Capability{timeWindowCap(`{"start":"23:59","end":"23:59"}`)}
	done := make(chan struct{})
	close(done)
	violated := make(chan string, 1)
	go ConstraintRecheckLoop(cons, nil, "", 10*time.Millisecond, done, func(reason string) {
		violated <- reason
	})
	select {
	case r := <-violated:
		t.Fatalf("done-closed loop should not fire, got %q", r)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestConstraintRecheckLoopPAConstraints G3: PA constraints are also rechecked
// (AIC empty, PA expired -> triggers violation).
func TestConstraintRecheckLoopPAConstraints(t *testing.T) {
	paCons := []Capability{timeWindowCap(`{"start":"23:59","end":"23:59"}`)}
	done := make(chan struct{})
	violated := make(chan string, 1)
	go ConstraintRecheckLoop(nil, paCons, "", 20*time.Millisecond, done, func(reason string) {
		select {
		case violated <- reason:
		default:
		}
	})
	select {
	case reason := <-violated:
		if !strings.Contains(reason, "time-window") {
			t.Fatalf("expected time-window violation, got %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected PA constraint violation, loop never fired")
	}
	close(done)

	// TestConstraintSchemeCanonical verifies the canonical constraint scheme
	// varwof/constraint-v1 is recognized (03-validation C2) alongside the
	// legacy values.

}

func TestConstraintSchemeCanonical(t *testing.T) {
	cs := []Capability{{
		SchemeId:     "varwof/constraint-v1",
		CapabilityId: ConstraintCIDRKey,
		Parameters:   []byte(`["10.0.0.0/8"]`),
	}}
	if err := CheckAuthorizationConstraints(cs, "10.1.2.3"); err != nil {
		t.Fatalf("canonical constraint scheme should evaluate: %v", err)
	}
	if u := firstUnknownConstraint(cs); u != nil {
		t.Fatalf("recognized constraint must not be flagged unknown: %+v", u)
	}
	unknown := []Capability{{
		SchemeId:     "varwof/constraint-v1",
		CapabilityId: "future-type",
		Parameters:   []byte(`{}`),
	}}
	if u := firstUnknownConstraint(unknown); u == nil {
		t.Fatalf("unknown constraint type under canonical scheme must be detected")
	}
	// non-constraint schemes are business capabilities, not constraints.
	biz := []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}}
	if u := firstUnknownConstraint(biz); u != nil {
		t.Fatalf("business capability must not be treated as an unknown constraint")
	}
}
