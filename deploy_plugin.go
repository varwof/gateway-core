// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// deployPlugin enforces the std/deploy-v1 capability contract at the
// operation layer: deployment/infra/secret operations must stay within the
// environment, namespace, resource, secret, and replica bounds declared in
// the AIC capability.
type deployPlugin struct {
	scheme string
}

func newDeployPlugin(scheme string, cfg map[string]interface{}) (*deployPlugin, error) {
	return &deployPlugin{scheme: scheme}, nil
}

func (p *deployPlugin) Scheme() string { return p.scheme }

func (p *deployPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if len(cap.Parameters) == 0 {
		return &PluginResult{Decision: PluginAllow,
			Reason: "deploy capability unconstrained (no parameter boundary)"}, nil
	}
	var bound struct {
		Environments []string `json:"environments"`
		Namespaces   []string `json:"namespaces"`
		Resources    []string `json:"resources"`
		Secrets      []string `json:"secrets"`
		MaxReplicas  int      `json:"max_replicas"`
	}
	if err := json.Unmarshal(cap.Parameters, &bound); err != nil {
		return &PluginResult{Decision: PluginDeny,
			Reason: "deploy capability parameters malformed"}, nil
	}

	op := deployOperationFromContext(ctx)

	if len(bound.Environments) > 0 && op.Environment != "" && !contains(bound.Environments, op.Environment) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("environment %q not in authorized set %v", op.Environment, bound.Environments)}, nil
	}
	if len(bound.Namespaces) > 0 && op.Namespace != "" && !contains(bound.Namespaces, op.Namespace) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("namespace %q not in authorized set %v", op.Namespace, bound.Namespaces)}, nil
	}
	if len(bound.Resources) > 0 && op.Resource != "" && !contains(bound.Resources, op.Resource) {
		return &PluginResult{Decision: PluginDeny,
			Reason: fmt.Sprintf("resource %q not in authorized set %v", op.Resource, bound.Resources)}, nil
	}

	switch cap.CapabilityId {
	case "secret:read":
		if len(bound.Secrets) > 0 && op.Secret != "" && !contains(bound.Secrets, op.Secret) {
			return &PluginResult{Decision: PluginDeny,
				Reason: fmt.Sprintf("secret %q not in allowlist %v", op.Secret, bound.Secrets)}, nil
		}
	case "deploy:apply":
		if bound.MaxReplicas > 0 && op.Replicas > bound.MaxReplicas {
			return &PluginResult{Decision: PluginDeny,
				Reason: fmt.Sprintf("replicas %d exceed maximum %d", op.Replicas, bound.MaxReplicas)}, nil
		}
	}
	return &PluginResult{Decision: PluginAllow,
		Reason: "operation within deploy capability boundary"}, nil
}

type deployOperation struct {
	Environment string
	Namespace   string
	Resource    string
	Secret      string
	Replicas    int
}

func deployOperationFromContext(ctx *PluginContext) deployOperation {
	var op deployOperation
	if len(ctx.Body) > 0 {
		var b struct {
			Environment string `json:"environment"`
			Namespace   string `json:"namespace"`
			Resource    string `json:"resource"`
			Secret      string `json:"secret"`
			Replicas    int    `json:"replicas"`
		}
		if json.Unmarshal(ctx.Body, &b) == nil {
			op.Environment, op.Namespace = b.Environment, b.Namespace
			op.Resource, op.Secret, op.Replicas = b.Resource, b.Secret, b.Replicas
			return op
		}
	}
	if q := ctx.Query["environment"]; len(q) > 0 {
		op.Environment = q[0]
	}
	if q := ctx.Query["namespace"]; len(q) > 0 {
		op.Namespace = q[0]
	}
	if q := ctx.Query["resource"]; len(q) > 0 {
		op.Resource = q[0]
	}
	if q := ctx.Query["secret"]; len(q) > 0 {
		op.Secret = q[0]
	}
	if q := ctx.Query["replicas"]; len(q) > 0 {
		op.Replicas, _ = strconv.Atoi(q[0])
	}
	return op
}
