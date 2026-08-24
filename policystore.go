// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// PolicySnapshot is a policy version snapshot (task 5a: policy config versioning + anti-rollback).
type PolicySnapshot struct {
	// Version is the policy version number (monotonically increasing, never decreases).
	Version uint64 `json:"version"`
	// Source is the origin: SIGHUP / API.
	Source string `json:"source"`
	// Operator is the operator (for API, it is the client certificate CN).
	Operator string `json:"operator,omitempty"`
	// RolledBackFrom records which version this rollback was initiated from (if applicable).
	RolledBackFrom uint64 `json:"rolled_back_from,omitempty"`
	// Timestamp is the creation time (RFC3339).
	Timestamp time.Time `json:"timestamp"`
	// Configs is the plugin configuration for this version (full snapshot, rebuildable on rollback).
	Configs PluginConfigs `json:"configs"`
}

// PolicyBranch defines policy branch rules (task 5b: branch control/canary).
// Routes specific agents to designated policy versions by agent identifier,
// enabling canary deployments and multi-policy lines.
type PolicyBranch struct {
	// ID is the unique branch identifier (e.g., "canary-agent-x").
	ID string `json:"id"`
	// AgentID is the match pattern: exact "a-123" / prefix "a-*" / wildcard "*".
	AgentID string `json:"agent_id"`
	// Version is the policy version number effective when this branch is matched (must be published).
	Version uint64 `json:"version"`
	// Priority determines match order (higher wins); default 0.
	Priority int `json:"priority"`
	// Comment describes the branch (canary scope, rollback plan, etc.).
	Comment string `json:"comment,omitempty"`
}

// PolicyManager manages the versioned lifecycle of the entire policy bundle (PluginConfigs):
// monotonically increasing version numbers, historical snapshots (configurable limit),
// rollback (generates new version numbers), branch control (select version by agent
// identifier, task 5b), and effective version query at decision time (task 5a).
// Compared to LEE US12676749B1 policy epoch, kept lightweight (does not enable
// "prevent rollback to before X" by default).
type PolicyManager struct {
	mu       sync.RWMutex
	registry *PluginRegistry
	// MaxHistory is the maximum number of historical snapshots retained (default 64).
	MaxHistory int
	// MinRollbackVersion prevents rollback to versions earlier than this (0=disabled).
	MinRollbackVersion uint64
	// current is the current version number.
	current uint64
	// history is the version snapshot history (ascending, newest at the end).
	history []*PolicySnapshot
	// active is the currently active version.
	active *PolicySnapshot
	// versionRegistries maps each version to an independent plugin registry snapshot
	// (for branch selection, does not pollute active).
	versionRegistries map[uint64]*PluginRegistry
	// branches are branch rules (matched in descending Priority order).
	branches []*PolicyBranch
}

// NewPolicyManager creates a policy manager, binding to the target registry.
func NewPolicyManager(registry *PluginRegistry) *PolicyManager {
	if registry == nil {
		registry = NewPluginRegistry()
	}
	return &PolicyManager{
		registry:          registry,
		MaxHistory:        64,
		versionRegistries: make(map[uint64]*PluginRegistry),
	}
}

// Registry returns the bound registry.
func (pm *PolicyManager) Registry() *PluginRegistry { return pm.registry }

// CurrentVersion returns the currently active policy version number.
func (pm *PolicyManager) CurrentVersion() uint64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.current
}

// ActiveSnapshot returns the currently active version snapshot.
func (pm *PolicyManager) ActiveSnapshot() *PolicySnapshot {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.active
}

// History returns historical snapshots (including current, ascending order).
func (pm *PolicyManager) History() []*PolicySnapshot {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]*PolicySnapshot, 0, len(pm.history))
	for _, s := range pm.history {
		cp := *s
		out = append(out, &cp)
	}
	return out
}

// Publish publishes a new version and applies it to the registry (shared by PUT /plugins and SIGHUP).
// source is "api" or "sighup"; operator is the API operator CN (may be empty for SIGHUP).
// Returns the new version number.
func (pm *PolicyManager) Publish(configs PluginConfigs, source, operator string) (uint64, error) {
	if configs == nil {
		configs = PluginConfigs{}
	}
	if err := BuildPluginsFromConfig(pm.registry, configs); err != nil {
		return 0, err
	}
	snap := &PolicySnapshot{
		Version:   pm.nextVersion(),
		Source:    source,
		Operator:  operator,
		Timestamp: time.Now().UTC(),
		Configs:   configs,
	}
	pm.commit(snap)
	return snap.Version, nil
}

// Rollback rolls back to a specified version (generates a new version number, does not
// decrease the version number itself). Applies the snapshot of the specified version to
// rebuild the registry and records the rollback source.
func (pm *PolicyManager) Rollback(version uint64, source, operator string) (uint64, error) {
	pm.mu.RLock()
	var target *PolicySnapshot
	for _, s := range pm.history {
		if s.Version == version {
			cp := *s
			target = &cp
			break
		}
	}
	minRollback := pm.MinRollbackVersion
	pm.mu.RUnlock()
	if target == nil {
		return 0, fmt.Errorf("policy version %d not found", version)
	}
	if minRollback > 0 && target.Version < minRollback {
		return 0, fmt.Errorf("rollback to version %d blocked: min rollback version is %d", target.Version, minRollback)
	}
	if err := BuildPluginsFromConfig(pm.registry, target.Configs); err != nil {
		return 0, err
	}
	snap := &PolicySnapshot{
		Version:        pm.nextVersion(),
		Source:         source,
		Operator:       operator,
		RolledBackFrom: target.Version,
		Timestamp:      time.Now().UTC(),
		Configs:        target.Configs,
	}
	pm.commit(snap)
	return snap.Version, nil
}

// Reset resets to an empty policy (clears all version history, branches, and registry). For testing and full rebuild.
func (pm *PolicyManager) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.registry.Reset()
	pm.current = 0
	pm.history = nil
	pm.active = nil
	pm.versionRegistries = make(map[uint64]*PluginRegistry)
	pm.branches = nil
}

func (pm *PolicyManager) nextVersion() uint64 {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.current++
	return pm.current
}

func (pm *PolicyManager) commit(snap *PolicySnapshot) {
	reg := NewPluginRegistry()
	if err := BuildPluginsFromConfig(reg, snap.Configs); err != nil {
		reg = nil
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.history = append(pm.history, snap)
	if len(pm.history) > pm.MaxHistory {
		drop := len(pm.history) - pm.MaxHistory
		pm.history = append([]*PolicySnapshot(nil), pm.history[drop:]...)
	}
	pm.versionRegistries[snap.Version] = reg
	pm.active = snap
}

// SnapshotJSON returns the JSON representation of a version snapshot (for management API).
func (s *PolicySnapshot) SnapshotJSON() map[string]interface{} {
	out := map[string]interface{}{
		"version":   s.Version,
		"source":    s.Source,
		"timestamp": s.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	if s.Operator != "" {
		out["operator"] = s.Operator
	}
	if s.RolledBackFrom != 0 {
		out["rolled_back_from"] = s.RolledBackFrom
	}
	if s.Configs != nil {
		// Deep copy to prevent external mutations from polluting the snapshot
		cfgJSON, _ := json.Marshal(s.Configs)
		var cfg PluginConfigs
		_ = json.Unmarshal(cfgJSON, &cfg)
		out["configs"] = cfg
	}
	return out
}

// SetBranches fully replaces branch rules (task 5b: branch control/canary).
// Validates: ID uniqueness, non-empty AgentID, referenced version must be published.
// Any invalid entry causes the entire operation to be rejected.
func (pm *PolicyManager) SetBranches(branches []PolicyBranch) error {
	seen := make(map[string]struct{}, len(branches))
	for i := range branches {
		b := &branches[i]
		if b.ID == "" || b.AgentID == "" {
			return fmt.Errorf("branch %q: id and agent_id are required", b.ID)
		}
		if _, dup := seen[b.ID]; dup {
			return fmt.Errorf("duplicate branch id %q", b.ID)
		}
		seen[b.ID] = struct{}{}
		ok := pm.hasVersion(b.Version)
		if !ok {
			return fmt.Errorf("branch %q references unpublished version %d", b.ID, b.Version)
		}
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.branches = make([]*PolicyBranch, len(branches))
	for i := range branches {
		b := branches[i]
		pm.branches[i] = &b
	}
	return nil
}

// Branches returns the current branch rules (copy).
func (pm *PolicyManager) Branches() []PolicyBranch {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]PolicyBranch, 0, len(pm.branches))
	for _, b := range pm.branches {
		out = append(out, *b)
	}
	return out
}

// ClearBranches clears all branch rules (reverts to using the currently active version for all).
func (pm *PolicyManager) ClearBranches() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.branches = nil
}

// SelectRegistry selects the effective policy version and corresponding plugin registry
// by agent identifier (task 5b). Rules are matched in descending Priority order: a matching
// branch returns that version's registry and version number; no match returns the currently
// active version. version=0 means the current version.
func (pm *PolicyManager) SelectRegistry(agentID string) (uint64, *PluginRegistry) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	branches := make([]*PolicyBranch, len(pm.branches))
	copy(branches, pm.branches)
	sort.SliceStable(branches, func(i, j int) bool {
		return branches[i].Priority > branches[j].Priority
	})
	for _, b := range branches {
		if matchAgentPattern(agentID, b.AgentID) {
			if reg := pm.versionRegistries[b.Version]; reg != nil {
				return b.Version, reg
			}
		}
	}
	return pm.current, pm.registry
}

func (pm *PolicyManager) hasVersion(v uint64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if v == 0 {
		return false
	}
	for _, s := range pm.history {
		if s.Version == v {
			return true
		}
	}
	return false
}

// matchAgentPattern checks whether agentID matches a pattern.
// Pattern supports: exact "a-123" / prefix "a-*" / wildcard "*".
func matchAgentPattern(agentID, pattern string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(agentID, strings.TrimSuffix(pattern, "*"))
	default:
		return agentID == pattern
	}
}
