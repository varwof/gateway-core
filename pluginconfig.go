// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PluginConfig defines the plugin configuration for a single scheme (JSON serializable).
type PluginConfig struct {
	// Type is the plugin type: allowlist / denylist / rbac / webhook.
	Type string `json:"type"`
	// Config is the plugin-specific configuration (JSON serializable).
	Config map[string]interface{} `json:"config"`
}

// PluginConfigs is a schemeId-keyed plugin configuration map, supporting JSON hot reload.
type PluginConfigs map[string]*PluginConfig

// PluginTypeAllowlist/Denylist/RBAC/Webhook are built-in plugin type names.
const (
	PluginTypeAllowlist = "allowlist"
	PluginTypeDenylist  = "denylist"
	PluginTypeRBAC      = "rbac"
	PluginTypeWebhook   = "webhook"
)

// BuildPluginsFromConfig builds plugins from configuration and registers
// them to the registry. Resets first then registers all, ensuring a
// complete rebuild after config changes.
func BuildPluginsFromConfig(reg *PluginRegistry, cfgs PluginConfigs) error {
	reg.Reset()
	for scheme, pc := range cfgs {
		if pc == nil {
			continue
		}
		p, err := newPluginFromConfig(scheme, pc)
		if err != nil {
			return fmt.Errorf("plugin %q: %w", scheme, err)
		}
		if err := reg.Register(p); err != nil {
			return fmt.Errorf("plugin %q: %w", scheme, err)
		}
	}
	return nil
}

func newPluginFromConfig(scheme string, pc *PluginConfig) (CapabilityPlugin, error) {
	switch pc.Type {
	case PluginTypeAllowlist:
		return newAllowlistPlugin(scheme, pc.Config)
	case PluginTypeDenylist:
		return newDenylistPlugin(scheme, pc.Config)
	case PluginTypeRBAC:
		return newRBACPlugin(scheme, pc.Config)
	case PluginTypeWebhook:
		return newWebhookPlugin(scheme, pc.Config)
	case "database":
		return newDatabasePlugin(scheme, pc.Config)
	default:
		return nil, fmt.Errorf("unknown plugin type %q", pc.Type)
	}
}

// ---- allowlist ----

type allowlistPlugin struct {
	scheme      string
	allow       map[string]bool
	defaultDeny bool
}

func newAllowlistPlugin(scheme string, cfg map[string]interface{}) (*allowlistPlugin, error) {
	allow, err := stringListFromConfig(cfg, "allow")
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	allowSet := make(map[string]bool, len(allow))
	for _, a := range allow {
		allowSet[a] = true
	}
	defaultDeny := defaultActionIsDeny(cfg)
	return &allowlistPlugin{scheme: scheme, allow: allowSet, defaultDeny: defaultDeny}, nil
}

// Scheme returns the plugin scheme identifier.
func (p *allowlistPlugin) Scheme() string { return p.scheme }

// Execute executes the plugin decision.
func (p *allowlistPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if p.allow[cap.CapabilityId] {
		return &PluginResult{Decision: PluginAllow, Reason: "capability in allowlist"}, nil
	}
	if p.defaultDeny {
		return &PluginResult{Decision: PluginDeny, Reason: "capability not in allowlist"}, nil
	}
	return &PluginResult{Decision: PluginAllow, Reason: "allowlist default allow"}, nil
}

// ---- denylist ----

type denylistPlugin struct {
	scheme       string
	deny         map[string]bool
	defaultAllow bool
}

func newDenylistPlugin(scheme string, cfg map[string]interface{}) (*denylistPlugin, error) {
	deny, err := stringListFromConfig(cfg, "deny")
	if err != nil {
		return nil, fmt.Errorf("denylist: %w", err)
	}
	denySet := make(map[string]bool, len(deny))
	for _, d := range deny {
		denySet[d] = true
	}
	defaultAllow := !defaultActionIsDeny(cfg)
	return &denylistPlugin{scheme: scheme, deny: denySet, defaultAllow: defaultAllow}, nil
}

// Scheme returns the plugin scheme identifier.
func (p *denylistPlugin) Scheme() string { return p.scheme }

// Execute executes the plugin decision.
func (p *denylistPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if p.deny[cap.CapabilityId] {
		return &PluginResult{Decision: PluginDeny, Reason: "capability in denylist"}, nil
	}
	if p.defaultAllow {
		return &PluginResult{Decision: PluginAllow, Reason: "denylist default allow"}, nil
	}
	return &PluginResult{Decision: PluginDeny, Reason: "denylist default deny"}, nil
}

// ---- rbac ----

type rbacPlugin struct {
	scheme      string
	roleMap     map[string]map[string]bool // role → capabilityId set
	defaultDeny bool
}

func newRBACPlugin(scheme string, cfg map[string]interface{}) (*rbacPlugin, error) {
	raw, ok := cfg["role_map"]
	if !ok {
		return nil, fmt.Errorf("rbac: missing role_map")
	}
	rm, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rbac: role_map must be object")
	}
	roleMap := make(map[string]map[string]bool, len(rm))
	for role, capsRaw := range rm {
		caps, err := toCapSet(capsRaw)
		if err != nil {
			return nil, fmt.Errorf("rbac: role %q: %w", role, err)
		}
		roleMap[role] = caps
	}
	defaultDeny := defaultActionIsDeny(cfg)
	return &rbacPlugin{scheme: scheme, roleMap: roleMap, defaultDeny: defaultDeny}, nil
}

// Scheme returns the plugin scheme identifier.
func (p *rbacPlugin) Scheme() string { return p.scheme }

// Execute executes the plugin decision.
func (p *rbacPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	// Matches both bare CapabilityId (SELECT:*) and scheme-prefixed full name
	// (varwof/demo-mysql-v1:SELECT:*), compatible with both role_map config conventions;
	// role_map entries support glob patterns (* and a:b:* prefix, see MatchCapability),
	// where a single pattern can authorize multiple capability types.
	fullName := cap.CapabilityId
	if cap.SchemeId != "" {
		fullName = cap.SchemeId + ":" + cap.CapabilityId
	}
	for _, role := range ctx.Roles {
		if caps, ok := p.roleMap[role]; ok {
			for pattern := range caps {
				if MatchCapability(cap.CapabilityId, pattern) || MatchCapability(fullName, pattern) {
					return &PluginResult{Decision: PluginAllow, Reason: "capability authorized by role"}, nil
				}
			}
		}
	}
	if p.defaultDeny {
		return &PluginResult{Decision: PluginDeny, Reason: "no role authorizes this capability"}, nil
	}
	return &PluginResult{Decision: PluginAllow, Reason: "rbac default allow"}, nil
}

// ---- webhook ----

type webhookPlugin struct {
	scheme  string
	url     string
	client  *http.Client
	headers map[string]string
}

func newWebhookPlugin(scheme string, cfg map[string]interface{}) (*webhookPlugin, error) {
	url, ok := cfg["url"].(string)
	if !ok || url == "" {
		return nil, fmt.Errorf("webhook: missing or invalid url")
	}
	timeoutSec := 5
	if v, ok := cfg["timeout_sec"].(float64); ok && v > 0 {
		timeoutSec = int(v)
	}
	headers := map[string]string{}
	if rawHeaders, ok := cfg["headers"].(map[string]interface{}); ok {
		for k, v := range rawHeaders {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}
	return &webhookPlugin{
		scheme:  scheme,
		url:     url,
		client:  &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
		headers: headers,
	}, nil
}

// Scheme returns the plugin scheme identifier.
func (p *webhookPlugin) Scheme() string { return p.scheme }

type webhookRequest struct {
	SchemeID     string   `json:"scheme_id"`
	CapabilityID string   `json:"capability_id"`
	ClientCN     string   `json:"client_cn"`
	Roles        []string `json:"roles"`
	Principal    string   `json:"principal"`
}

type webhookResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// Execute executes the webhook plugin decision.
func (p *webhookPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	body := webhookRequest{
		SchemeID:     cap.SchemeId,
		CapabilityID: cap.CapabilityId,
		ClientCN:     ctx.ClientCN,
		Roles:        ctx.Roles,
	}
	if ctx.AIC != nil {
		body.Principal = ctx.AIC.PrincipalUid.String()
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx.Context, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook: call: %w", err)
	}
	defer resp.Body.Close()
	var wr webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		return nil, fmt.Errorf("webhook: decode response: %w", err)
	}
	switch wr.Decision {
	case "allow":
		return &PluginResult{Decision: PluginAllow, Reason: wr.Reason}, nil
	case "deny":
		return &PluginResult{Decision: PluginDeny, Reason: wr.Reason}, nil
	default:
		return nil, fmt.Errorf("webhook: unexpected decision %q", wr.Decision)
	}
}

// ---- helpers ----

func stringListFromConfig(cfg map[string]interface{}, key string) ([]string, error) {
	raw, ok := cfg[key]
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%q must be array of strings", key)
			}
			result = append(result, s)
		}
		return result, nil
	case []string:
		return v, nil
	default:
		return nil, fmt.Errorf("%q must be array of strings", key)
	}
}

// M19 fix: validate default_action enum — typos silently convert denylist to allow-all.
func defaultActionIsDeny(cfg map[string]interface{}) bool {
	v, ok := cfg["default_action"]
	if !ok {
		return true // default is deny
	}
	s, ok := v.(string)
	if !ok {
		return true
	}
	switch s {
	case "deny":
		return true
	case "allow":
		return false
	default:
		// Unknown value — treat as deny (fail-closed) to prevent silent misconfiguration.
		return true
	}
}

// PluginTypeName returns the human-readable type name of a plugin.
func PluginTypeName(p CapabilityPlugin) string {
	switch p.(type) {
	case *allowlistPlugin:
		return PluginTypeAllowlist
	case *denylistPlugin:
		return PluginTypeDenylist
	case *rbacPlugin:
		return PluginTypeRBAC
	case *webhookPlugin:
		return PluginTypeWebhook
	default:
		return fmt.Sprintf("custom(%T)", p)
	}
}

func toCapSet(raw interface{}) (map[string]bool, error) {
	switch v := raw.(type) {
	case []interface{}:
		capSet := make(map[string]bool, len(v))
		for _, c := range v {
			s, ok := c.(string)
			if !ok {
				return nil, fmt.Errorf("caps must be array of strings")
			}
			capSet[s] = true
		}
		return capSet, nil
	case []string:
		capSet := make(map[string]bool, len(v))
		for _, s := range v {
			capSet[s] = true
		}
		return capSet, nil
	default:
		return nil, fmt.Errorf("caps must be array of strings")
	}
}

// PluginSummary is the plugin summary returned by the management API.
type PluginSummary struct {
	Scheme string `json:"scheme"`
	Type   string `json:"type"`
}
