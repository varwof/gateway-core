// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ManagementServer is the unified management API server, supporting mTLS + RBAC.
type ManagementServer struct {
	mux      *http.ServeMux
	cfg      ManagementServerConfig
	handlers []routeHandler

	server    *http.Server
	mu        sync.Mutex
	stopGuard *StopGuard
}

// ManagementServerConfig is the management API server configuration.
type ManagementServerConfig struct {
	// Listen is the management API listen address (e.g. :9443).
	Listen string
	// TLSConfig is the mTLS server-side TLS configuration.
	TLSConfig *tls.Config
	// BuildInfo contains build information (version, build time, etc.).
	BuildInfo string
	// AuditLogger is the audit logger instance.
	AuditLogger *AuditLogger
	// AuditChain is the audit Merkle hash chain instance.
	AuditChain *AuditChain
	// Translator is the i18n translator instance.
	Translator Translator
	// Lang is the current language code (e.g. zh, en).
	Lang string
	// PluginRegistry is the capability plugin registry.
	PluginRegistry *PluginRegistry
	// PolicyManager is the policy versioning manager (task 5a: versioning/rollback/audit).
	// When nil, PUT /plugins degrades to unversioned direct rebuild, GET /policies/* returns 404.
	PolicyManager *PolicyManager
	// ConfirmedRenewalManager is the confirmed renewal state machine (P0-2, P2-A-12/17).
	ConfirmedRenewalManager *ConfirmedRenewalManager
	// AuditIndex is the audit FTS index (monitoring presentation: full-text search). Returns 404 when nil.
	AuditIndex *AuditIndex
	// ConnRegistry is the active connection registry (monitoring: real-time traffic/IP access points/agent directory).
	// Returns empty list when nil.
	ConnRegistry *ConnRegistry
	// ChainRefs is the cross-gateway audit chain reference store (DAG horizontal anchoring).
	// Returns empty peers when nil, but still returns the local chain head.
	ChainRefs *ChainRefStore
}

type routeHandler struct {
	pattern      string
	handler      http.HandlerFunc
	allowedRoles []string
}

// NewManagementServer creates a management API server instance.
func NewManagementServer(cfg ManagementServerConfig) *ManagementServer {
	ms := &ManagementServer{
		mux:       http.NewServeMux(),
		cfg:       cfg,
		stopGuard: NewStopGuard(),
	}
	ms.registerStandardRoutes()
	return ms
}

// RegisterHandler registers a management route with RBAC role protection.
func (ms *ManagementServer) RegisterHandler(pattern string, handler http.HandlerFunc, allowedRoles ...string) {
	if len(allowedRoles) > 0 {
		ms.mux.HandleFunc(pattern, withRoles(allowedRoles, handler, ms.cfg.Translator, ms.cfg.Lang))
	} else {
		ms.mux.HandleFunc(pattern, handler)
	}
}

// RegisterRawHandler registers a raw management route without RBAC checks.
func (ms *ManagementServer) RegisterRawHandler(pattern string, handler http.HandlerFunc) {
	ms.mux.HandleFunc(pattern, handler)
}

// Start starts the management API HTTP service.
func (ms *ManagementServer) Start() error {
	// Finding 12: role authorization (RequireRoles) reads role OUs from
	// r.TLS.PeerCertificates. If the server does not require and verify client
	// certificates, those roles are attacker-controlled. Refuse to start rather
	// than run an authorization bypass.
	if ms.cfg.TLSConfig == nil {
		return errors.New("management: TLSConfig is required (management API must run under mTLS)")
	}
	if ms.cfg.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("management: TLSConfig.ClientAuth must be tls.RequireAndVerifyClientCert; refusing to run with unverified client certificates (finding 12)")
	}
	srv := &http.Server{
		Addr:      ms.cfg.Listen,
		TLSConfig: ms.cfg.TLSConfig,
		Handler:   ms.mux,
	}
	ms.mu.Lock()
	ms.server = srv
	ms.mu.Unlock()
	return srv.ListenAndServeTLS("", "")
}

// Stop gracefully shuts down the management API service.
func (ms *ManagementServer) Stop() {
	ms.mu.Lock()
	srv := ms.server
	ms.mu.Unlock()
	if srv != nil {
		// W29 (2026-08-16): Graceful shutdown instead of hard Close — in-flight management
		// requests have a 5s drain window; SIGHUP reload does not abort ongoing management operations.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
}

// UpdatePluginRegistry updates the plugin registry reference on the management server (for hot reload).
func (ms *ManagementServer) UpdatePluginRegistry(reg *PluginRegistry) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.cfg.PluginRegistry = reg
}

// SetPolicyManager updates the policy versioning manager reference (for hot reload).
func (ms *ManagementServer) SetPolicyManager(pm *PolicyManager) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.cfg.PolicyManager = pm
}

// SetConfirmedRenewalManager sets the confirmed renewal manager reference (for hot reload).
func (ms *ManagementServer) SetConfirmedRenewalManager(m *ConfirmedRenewalManager) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.cfg.ConfirmedRenewalManager = m
}

func (ms *ManagementServer) registerStandardRoutes() {
	ms.RegisterRawHandler("/api/v1/gateway/health", handleHealth)
	ms.RegisterHandler("/api/v1/gateway/metrics",
		ms.makeMetricsHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("/api/v1/gateway/audit",
		ms.makeAuditHandler(),
		RoleAudit, RoleAdmin,
	)
	ms.RegisterHandler("/api/v1/gateway/audit/verify",
		ms.makeAuditVerifyHandler(),
		RoleAudit, RoleAdmin,
	)
	ms.RegisterHandler("GET /api/v1/gateway/plugins",
		ms.makePluginsHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("GET /api/v1/gateway/plugins/{scheme}",
		ms.makePluginBySchemeHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("PUT /api/v1/gateway/plugins",
		ms.makePutPluginsHandler(),
		RoleAdmin,
	)
	ms.RegisterHandler("DELETE /api/v1/gateway/plugins",
		ms.makeDeletePluginsHandler(),
		RoleAdmin,
	)
	// Task 5a: policy versioning + rollback (returns 404 when PolicyManager not configured)
	ms.RegisterHandler("GET /api/v1/gateway/policies/versions",
		ms.makePolicyVersionsHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("POST /api/v1/gateway/policies/rollback",
		ms.makePolicyRollbackHandler(),
		RoleAdmin,
	)
	// Task 5b: branch control/canary release (returns 404 when PolicyManager not configured)
	ms.RegisterHandler("GET /api/v1/gateway/policies/branches",
		ms.makePolicyBranchesHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("PUT /api/v1/gateway/policies/branches",
		ms.makePutPolicyBranchesHandler(),
		RoleAdmin,
	)
	ms.RegisterHandler("DELETE /api/v1/gateway/policies/branches",
		ms.makeClearPolicyBranchesHandler(),
		RoleAdmin,
	)
	// P0-2 confirmed renewal (P2-A-12/17): status/request/confirm/reject
	ms.RegisterHandler("GET /api/v1/gateway/renewal/status",
		MakeConfirmedRenewalStatusHandler(ms.cfg.ConfirmedRenewalManager, ms.cfg.Translator, ms.cfg.Lang),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("POST /api/v1/gateway/renewal/request",
		MakeConfirmedRenewalRequestHandler(ms.cfg.ConfirmedRenewalManager, ms.cfg.Translator, ms.cfg.Lang),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("POST /api/v1/gateway/renewal/confirm",
		MakeConfirmedRenewalConfirmHandler(ms.cfg.ConfirmedRenewalManager, ms.cfg.Translator, ms.cfg.Lang),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("POST /api/v1/gateway/renewal/reject",
		MakeConfirmedRenewalRejectHandler(ms.cfg.ConfirmedRenewalManager, ms.cfg.Translator, ms.cfg.Lang),
		RoleAdmin,
	)
	// Monitoring presentation layer (2026-08-15): audit full-text search / real-time connections / IP access points / agent directory
	ms.RegisterHandler("GET /api/v1/gateway/audit/search",
		ms.makeAuditSearchHandler(),
		RoleAudit, RoleAdmin,
	)
	ms.RegisterHandler("GET /api/v1/gateway/connections",
		ms.makeConnectionsHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("GET /api/v1/gateway/access-points",
		ms.makeAccessPointsHandler(),
		RoleOps, RoleAdmin,
	)
	ms.RegisterHandler("GET /api/v1/gateway/agents",
		ms.makeAgentsHandler(),
		RoleOps, RoleAdmin,
	)
	// Cross-gateway audit chain DAG references (2026-08-15): local chain head + peer gateway chain references
	ms.RegisterHandler("GET /api/v1/gateway/audit/chain",
		ms.makeChainRefsHandler(),
		RoleAudit, RoleAdmin,
	)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	WriteMgmtJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (ms *ManagementServer) makeMetricsHandler() http.HandlerFunc {
	buildInfo := ms.cfg.BuildInfo
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(RenderMetrics(buildInfo)))
	}
}

func (ms *ManagementServer) makeAuditHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ms.cfg.AuditLogger == nil || ms.cfg.AuditLogger.File() == "" {
			WriteMgmtError(w, http.StatusNotFound, "audit not configured")
			return
		}

		q := r.URL.Query()
		var sinceTime, untilTime time.Time
		if s := q.Get("since"); s != "" {
			var err error
			sinceTime, err = time.Parse(time.RFC3339, s)
			if err != nil {
				WriteMgmtError(w, http.StatusBadRequest, "invalid since format (use RFC3339)")
				return
			}
		}
		if s := q.Get("until"); s != "" {
			var err error
			untilTime, err = time.Parse(time.RFC3339, s)
			if err != nil {
				WriteMgmtError(w, http.StatusBadRequest, "invalid until format (use RFC3339)")
				return
			}
		}

		limit := 0
		if s := q.Get("limit"); s != "" {
			limit, _ = strconv.Atoi(s)
			if limit < 0 {
				limit = 0
			}
		}
		offset := 0
		if s := q.Get("offset"); s != "" {
			offset, _ = strconv.Atoi(s)
			if offset < 0 {
				offset = 0
			}
		}

		sort := q.Get("sort")
		if sort == "" {
			sort = "asc"
		}

		entries, err := ReadAuditEntries(ms.cfg.AuditLogger.File(), AuditFilter{
			Since:    sinceTime,
			Until:    untilTime,
			Limit:    limit,
			Offset:   offset,
			Sort:     sort,
			Action:   q.Get("action"),
			ClientCN: q.Get("cn"),
			Serial:   q.Get("serial"),
			Mapping:  q.Get("mapping"),
		})
		if err != nil {
			WriteMgmtError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteMgmtJSON(w, http.StatusOK, entries)
	}
}

func (ms *ManagementServer) makeAuditVerifyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteMgmtError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}
		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteMgmtError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp := ms.cfg.AuditChain.VerifyJSON(&req)
		WriteMgmtJSON(w, http.StatusOK, resp)
	}
}

// makeAuditSearchHandler handles audit full-text search
// (GET /api/v1/gateway/audit/search?q=&action=&agent_id=&mapping=&client_cn=&since=&until=&limit=,
// RoleAudit/RoleAdmin).
// Depends on ManagementServerConfig.AuditIndex (FTS index); returns 404 when not configured.
func (ms *ManagementServer) makeAuditSearchHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ms.cfg.AuditIndex == nil {
			WriteMgmtError(w, http.StatusNotFound, "audit index not configured")
			return
		}
		q := r.URL.Query().Get("q")
		limit := 50
		if s := r.URL.Query().Get("limit"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		action := r.URL.Query().Get("action")
		agentID := r.URL.Query().Get("agent_id")
		mapping := r.URL.Query().Get("mapping")
		cn := r.URL.Query().Get("client_cn")
		var since, until int64
		if s := r.URL.Query().Get("since"); s != "" {
			since, _ = strconv.ParseInt(s, 10, 64)
		}
		if s := r.URL.Query().Get("until"); s != "" {
			until, _ = strconv.ParseInt(s, 10, 64)
		}

		var entries []AuditIndexEntry
		var err error
		switch {
		case q != "":
			entries, err = ms.cfg.AuditIndex.SearchFTS(q, limit*5)
		case cn != "":
			entries, err = ms.cfg.AuditIndex.Search(&AuditIndexQuery{CN: cn, Since: since, Until: until, Limit: limit * 5})
		default:
			entries, err = ms.cfg.AuditIndex.Search(&AuditIndexQuery{Since: since, Until: until, Limit: limit * 5})
		}
		if err != nil {
			WriteMgmtError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// In-memory filtering: action / agent_id / mapping
		type auditHit struct {
			Hash  string      `json:"hash"`
			Entry *AuditEntry `json:"entry"`
		}
		results := make([]auditHit, 0, limit)
		for _, e := range entries {
			if len(results) >= limit {
				break
			}
			if action != "" && e.Action != action {
				continue
			}
			var full AuditEntry
			if e.RawEntry != "" {
				if err := json.Unmarshal([]byte(e.RawEntry), &full); err != nil {
					continue
				}
			}
			if agentID != "" && full.AgentId != agentID {
				continue
			}
			if mapping != "" && full.Mapping != mapping {
				continue
			}
			hit := auditHit{Hash: e.Hash}
			if e.RawEntry != "" {
				hit.Entry = &full
			}
			results = append(results, hit)
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"results": results,
			"count":   len(results),
		})
	}
}

// makeConnectionsHandler handles real-time connection details
// (GET /api/v1/gateway/connections, RoleOps/RoleAdmin). Returns empty list when registry not configured.
func (ms *ManagementServer) makeConnectionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg := ms.cfg.ConnRegistry
		if reg == nil {
			WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{"connections": []ConnectionInfo{}})
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{"connections": reg.ListConnections()})
	}
}

// makeAccessPointsHandler handles IP access point statistics
// (GET /api/v1/gateway/access-points, RoleOps/RoleAdmin). Returns empty list when registry not configured.
func (ms *ManagementServer) makeAccessPointsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg := ms.cfg.ConnRegistry
		if reg == nil {
			WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{"access_points": []map[string]interface{}{}})
			return
		}
		byIP := make(map[string]*accessPointAgg)
		for _, ci := range reg.ListConnections() {
			if ci.SrcIP == "" {
				continue
			}
			agg := byIP[ci.SrcIP]
			if agg == nil {
				agg = &accessPointAgg{SrcIP: ci.SrcIP}
				byIP[ci.SrcIP] = agg
			}
			agg.Connections++
			agg.addAgent(ci.AgentId)
			agg.addProtocol(ci.Protocol)
		}
		out := make([]*accessPointAgg, 0, len(byIP))
		for _, agg := range byIP {
			out = append(out, agg)
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{"access_points": out})
	}
}

// makeAgentsHandler handles active agent directory
// (GET /api/v1/gateway/agents, RoleOps/RoleAdmin). Returns empty list when registry not configured.
func (ms *ManagementServer) makeAgentsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg := ms.cfg.ConnRegistry
		if reg == nil {
			WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{"agents": []map[string]interface{}{}})
			return
		}
		byAgent := make(map[string]*agentStatusAgg)
		for _, ci := range reg.ListConnections() {
			if ci.AgentId == "" {
				continue
			}
			agg := byAgent[ci.AgentId]
			if agg == nil {
				agg = &agentStatusAgg{AgentId: ci.AgentId, Principal: ci.PrincipalUid}
				byAgent[ci.AgentId] = agg
			}
			agg.Connections++
			agg.addProtocol(ci.Protocol)
			agg.addIP(ci.SrcIP)
			if ci.Established > agg.LastSeen {
				agg.LastSeen = ci.Established
			}
			if agg.Serial == "" {
				agg.Serial = ci.Serial
			}
		}
		out := make([]*agentStatusAgg, 0, len(byAgent))
		for _, agg := range byAgent {
			out = append(out, agg)
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{"agents": out})
	}
}

// makeChainRefsHandler handles cross-gateway audit chain references
// (GET /api/v1/gateway/audit/chain, RoleAudit/RoleAdmin).
// Returns local audit chain head (local) + peer gateway chain references (peers).
// Peer gateways can verify reference consistency from this, forming a cross-gateway audit evidence DAG.
func (ms *ManagementServer) makeChainRefsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var local *SealedTree
		if chain := ms.cfg.AuditChain; chain != nil {
			n := chain.BatchCount()
			if n > 0 {
				local = chain.GetTree(n - 1)
			}
		}
		var peers []ChainRef
		if store := ms.cfg.ChainRefs; store != nil {
			peers = store.PeerRefs()
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"local": local,
			"peers": peers,
		})
	}
}

type accessPointAgg struct {
	SrcIP       string   `json:"src_ip"`
	Connections int      `json:"connections"`
	Agents      []string `json:"agents,omitempty"`
	Protocols   []string `json:"protocols,omitempty"`
}

func (a *accessPointAgg) addAgent(agent string) {
	if agent == "" {
		return
	}
	for _, x := range a.Agents {
		if x == agent {
			return
		}
	}
	a.Agents = append(a.Agents, agent)
}

func (a *accessPointAgg) addProtocol(p string) {
	if p == "" {
		return
	}
	for _, x := range a.Protocols {
		if x == p {
			return
		}
	}
	a.Protocols = append(a.Protocols, p)
}

type agentStatusAgg struct {
	AgentId     string   `json:"agent_id"`
	Principal   string   `json:"principal,omitempty"`
	Connections int      `json:"connections"`
	Protocols   []string `json:"protocols,omitempty"`
	SrcIPs      []string `json:"src_ips,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	LastSeen    int64    `json:"last_seen,omitempty"`
}

func (a *agentStatusAgg) addProtocol(p string) {
	if p == "" {
		return
	}
	for _, x := range a.Protocols {
		if x == p {
			return
		}
	}
	a.Protocols = append(a.Protocols, p)
}

func (a *agentStatusAgg) addIP(ip string) {
	if ip == "" {
		return
	}
	for _, x := range a.SrcIPs {
		if x == ip {
			return
		}
	}
	a.SrcIPs = append(a.SrcIPs, ip)
}

func (ms *ManagementServer) makePluginsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg := ms.cfg.PluginRegistry
		summaries := []PluginSummary{}
		if reg != nil {
			for _, scheme := range reg.Keys() {
				p, err := reg.Find(scheme)
				if err == nil {
					summaries = append(summaries, PluginSummary{
						Scheme: p.Scheme(),
						Type:   PluginTypeName(p),
					})
				}
			}
		}
		WriteMgmtJSON(w, http.StatusOK, summaries)
	}
}

func (ms *ManagementServer) makePluginBySchemeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme := r.PathValue("scheme")
		reg := ms.cfg.PluginRegistry
		if reg == nil {
			WriteMgmtError(w, http.StatusNotFound, "plugin registry not configured")
			return
		}
		p, err := reg.Find(scheme)
		if err != nil {
			WriteMgmtError(w, http.StatusNotFound, "plugin not found")
			return
		}
		WriteMgmtJSON(w, http.StatusOK, PluginSummary{
			Scheme: p.Scheme(),
			Type:   PluginTypeName(p),
		})
	}
}

func (ms *ManagementServer) makePutPluginsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg := ms.cfg.PluginRegistry
		if reg == nil {
			WriteMgmtError(w, http.StatusServiceUnavailable, "plugin registry not configured")
			return
		}
		var cfgs PluginConfigs
		if err := json.NewDecoder(r.Body).Decode(&cfgs); err != nil {
			WriteMgmtError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if cfgs == nil {
			cfgs = PluginConfigs{}
		}
		operator := peerCN(r)
		if pm := ms.cfg.PolicyManager; pm != nil {
			if pm.Registry() != reg {
				WriteMgmtError(w, http.StatusServiceUnavailable, "policy manager not bound to active registry")
				return
			}
			version, err := pm.Publish(cfgs, "api", operator)
			if err != nil {
				WriteMgmtError(w, http.StatusBadRequest, err.Error())
				return
			}
			WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
				"status": "ok", "action": "plugins_replaced",
				"policy_version": version,
			})
			return
		}
		if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
			WriteMgmtError(w, http.StatusBadRequest, err.Error())
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": "plugins_replaced"})
	}
}

// makePolicyVersionsHandler lists all policy version snapshots (task 5a).
func (ms *ManagementServer) makePolicyVersionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pm := ms.cfg.PolicyManager
		if pm == nil {
			WriteMgmtError(w, http.StatusNotFound, "policy manager not configured")
			return
		}
		hist := pm.History()
		items := make([]map[string]interface{}, 0, len(hist))
		for _, s := range hist {
			items = append(items, s.SnapshotJSON())
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"current_version": pm.CurrentVersion(),
			"count":           len(items),
			"versions":        items,
		})
	}
}

// makePolicyRollbackHandler rolls back policy to a specified version (task 5a).
// Request body: {"version": <uint64>}; produces a new version number without overwriting history.
func (ms *ManagementServer) makePolicyRollbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pm := ms.cfg.PolicyManager
		if pm == nil {
			WriteMgmtError(w, http.StatusNotFound, "policy manager not configured")
			return
		}
		var req struct {
			Version uint64 `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Version == 0 {
			WriteMgmtError(w, http.StatusBadRequest, "invalid JSON: {\"version\": <uint64>} required")
			return
		}
		version, err := pm.Rollback(req.Version, "api", peerCN(r))
		if err != nil {
			WriteMgmtError(w, http.StatusBadRequest, err.Error())
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ok", "action": "policy_rolled_back",
			"new_version": version,
		})
	}
}

// makePolicyBranchesHandler lists current branch rules (task 5b).
func (ms *ManagementServer) makePolicyBranchesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pm := ms.cfg.PolicyManager
		if pm == nil {
			WriteMgmtError(w, http.StatusNotFound, "policy manager not configured")
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"current_version": pm.CurrentVersion(),
			"count":           len(pm.Branches()),
			"branches":        pm.Branches(),
		})
	}
}

// makePutPolicyBranchesHandler replaces all branch rules (task 5b).
// Request body: {"branches": [{"id": "...", "agent_id": "...", "version": <uint64>, "priority": <int>}]}
func (ms *ManagementServer) makePutPolicyBranchesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pm := ms.cfg.PolicyManager
		if pm == nil {
			WriteMgmtError(w, http.StatusNotFound, "policy manager not configured")
			return
		}
		var req struct {
			Branches []PolicyBranch `json:"branches"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteMgmtError(w, http.StatusBadRequest, "invalid JSON: {\"branches\": [...]} required")
			return
		}
		if err := pm.SetBranches(req.Branches); err != nil {
			WriteMgmtError(w, http.StatusBadRequest, err.Error())
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ok", "action": "policy_branches_replaced",
			"count": len(req.Branches),
		})
	}
}

// makeClearPolicyBranchesHandler clears all branch rules (reverts to full routing on current version).
func (ms *ManagementServer) makeClearPolicyBranchesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pm := ms.cfg.PolicyManager
		if pm == nil {
			WriteMgmtError(w, http.StatusNotFound, "policy manager not configured")
			return
		}
		pm.ClearBranches()
		WriteMgmtJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": "policy_branches_cleared"})
	}
}

// peerCN extracts the mTLS client certificate CN as the operator identifier.
func peerCN(r *http.Request) string {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

func (ms *ManagementServer) makeDeletePluginsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg := ms.cfg.PluginRegistry
		if reg == nil {
			WriteMgmtError(w, http.StatusServiceUnavailable, "plugin registry not configured")
			return
		}
		reg.Reset()
		WriteMgmtJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": "plugins_cleared"})
	}
}

func withRoles(allowed []string, next http.HandlerFunc, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireRoles(r, allowed) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				WriteMgmtError(w, http.StatusUnauthorized, tOrDefault(tr, lang, "auth.mtls_required", "mTLS required"))
			} else {
				WriteMgmtError(w, http.StatusForbidden, tOrDefault(tr, lang, "auth.admin_required", "insufficient permissions"))
			}
			return
		}
		next(w, r)
	}
}

// WriteMgmtJSON writes a management API JSON success response.
func WriteMgmtJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// WriteMgmtError writes a management API JSON error response.
func WriteMgmtError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// MakeDisconnectByAgentHandler returns an HTTP handler that disconnects all
// connections for a given agent_id. Request: POST with JSON body {"agent_id": "..."}.
func MakeDisconnectByAgentHandler(registry *ConnRegistry, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteMgmtError(w, http.StatusMethodNotAllowed,
				tOrDefault(tr, lang, "api.method_not_allowed", "method not allowed"))
			return
		}
		var req struct {
			AgentId string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteMgmtError(w, http.StatusBadRequest,
				tOrDefault(tr, lang, "api.invalid_body", "invalid request body"))
			return
		}
		if req.AgentId == "" {
			WriteMgmtError(w, http.StatusBadRequest,
				tOrDefault(tr, lang, "api.missing_agent_id", "agent_id is required"))
			return
		}
		count := registry.DisconnectByAgentId(req.AgentId)
		WriteMgmtJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "disconnected": count, "agent_id": req.AgentId,
		})
	}
}

// MakeDisconnectByUserHandler returns an HTTP handler that disconnects all
// connections for a given principalUid. Request: POST with JSON body {"principal_uid": "..."}.
func MakeDisconnectByUserHandler(registry *ConnRegistry, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			WriteMgmtError(w, http.StatusMethodNotAllowed,
				tOrDefault(tr, lang, "api.method_not_allowed", "method not allowed"))
			return
		}
		var req struct {
			PrincipalUid string `json:"principal_uid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteMgmtError(w, http.StatusBadRequest,
				tOrDefault(tr, lang, "api.invalid_body", "invalid request body"))
			return
		}
		if req.PrincipalUid == "" {
			WriteMgmtError(w, http.StatusBadRequest,
				tOrDefault(tr, lang, "api.missing_principal_uid", "principal_uid is required"))
			return
		}
		count := registry.DisconnectByPrincipalUid(req.PrincipalUid)
		WriteMgmtJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "disconnected": count, "principal_uid": req.PrincipalUid,
		})
	}
}

func tOrDefault(tr Translator, lang, key, fallback string) string {
	if tr != nil {
		if s := tr.T(lang, key); s != key {
			return s
		}
	}
	return fallback
}

// MakeConfirmedRenewalStatusHandler returns a handler for querying confirmed renewal status
// (GET /api/v1/gateway/renewal/status, RoleOps/RoleAdmin).
func MakeConfirmedRenewalStatusHandler(m *ConfirmedRenewalManager, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			WriteMgmtError(w, http.StatusServiceUnavailable, "confirmed renewal not configured")
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"status":     m.State().String(),
			"session_id": m.CurrentSessionID(),
			"reason":     m.Reason(),
		})
	}
}

// MakeConfirmedRenewalRequestHandler returns a handler for initiating confirmed renewal
// (POST /api/v1/gateway/renewal/request, RoleOps/RoleAdmin).
// Request body: {session_id, ca, cn, san, agent_id, principal_uid, old_serial, validity, profile, capabilities[]}
// After triggering renewal, enters "awaiting responsible party confirmation" state (P2-A-12).
func MakeConfirmedRenewalRequestHandler(m *ConfirmedRenewalManager, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			WriteMgmtError(w, http.StatusServiceUnavailable, "confirmed renewal not configured")
			return
		}
		if r.Method != http.MethodPost {
			WriteMgmtError(w, http.StatusMethodNotAllowed,
				tOrDefault(tr, lang, "api.method_not_allowed", "method not allowed"))
			return
		}
		var req RenewalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteMgmtError(w, http.StatusBadRequest,
				tOrDefault(tr, lang, "api.invalid_body", "invalid request body"))
			return
		}
		if req.SessionID == "" || req.CN == "" {
			WriteMgmtError(w, http.StatusBadRequest, "session_id and cn are required")
			return
		}
		// Two-party control (finding 2): record the authenticated requester
		// identity server-side so Confirm can refuse self-approval.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			req.RequesterKeyHash = KeyHashHex(r.TLS.PeerCertificates[0])
		}
		if err := m.RequestRenewal(&req); err != nil {
			WriteMgmtError(w, http.StatusConflict, err.Error())
			return
		}
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"status":     RenewalAwaitingConfirmation.String(),
			"session_id": req.SessionID,
		})
	}
}

// MakeConfirmedRenewalConfirmHandler returns a handler for responsible-party renewal confirmation
// (POST /api/v1/gateway/renewal/confirm, RoleOps/RoleAdmin).
// Request body: {session_id, principal_cert_pem, da{...}} — DA is re-signed by the responsible
// party using their private key via SignRenewalDA (new nonce/timestamp/requestedLifetime).
// Gateway verifies DA signature + permission recheck (capabilities ⊆ PA grants),
// rejecting renewal on escalation (P2-A-17).
func MakeConfirmedRenewalConfirmHandler(m *ConfirmedRenewalManager, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			WriteMgmtError(w, http.StatusServiceUnavailable, "confirmed renewal not configured")
			return
		}
		if r.Method != http.MethodPost {
			WriteMgmtError(w, http.StatusMethodNotAllowed,
				tOrDefault(tr, lang, "api.method_not_allowed", "method not allowed"))
			return
		}
		var body struct {
			SessionID        string           `json:"session_id"`
			PrincipalCertPEM string           `json:"principal_cert_pem"`
			DA               RenewalDAPayload `json:"da"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			WriteMgmtError(w, http.StatusBadRequest,
				tOrDefault(tr, lang, "api.invalid_body", "invalid request body"))
			return
		}
		principalCert, err := ParsePEMCert([]byte(body.PrincipalCertPEM))
		if err != nil {
			WriteMgmtError(w, http.StatusBadRequest, "invalid principal_cert_pem: "+err.Error())
			return
		}
		da, err := body.DA.toDelegationAuthorization()
		if err != nil {
			WriteMgmtError(w, http.StatusBadRequest, "invalid da: "+err.Error())
			return
		}
		issued, err := m.Confirm(&RenewalConfirmation{
			SessionID:     body.SessionID,
			DA:            da,
			PrincipalCert: principalCert,
		})
		if err != nil {
			WriteMgmtError(w, http.StatusConflict, err.Error())
			return
		}
		resp := map[string]interface{}{
			"status": RenewalConfirmed.String(),
		}
		if issued != nil {
			resp["serial_number"] = issued.SerialNumber
			resp["cert_pem"] = issued.CertPEM
			resp["key_pem"] = issued.KeyPEM
		}
		WriteMgmtJSON(w, http.StatusOK, resp)
	}
}

// MakeConfirmedRenewalRejectHandler returns a handler for rejecting renewal
// (POST /api/v1/gateway/renewal/reject, RoleAdmin).
func MakeConfirmedRenewalRejectHandler(m *ConfirmedRenewalManager, tr Translator, lang string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			WriteMgmtError(w, http.StatusServiceUnavailable, "confirmed renewal not configured")
			return
		}
		if r.Method != http.MethodPost {
			WriteMgmtError(w, http.StatusMethodNotAllowed,
				tOrDefault(tr, lang, "api.method_not_allowed", "method not allowed"))
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.Reject(body.Reason)
		WriteMgmtJSON(w, http.StatusOK, map[string]interface{}{
			"status": RenewalRejected.String(),
			"reason": m.Reason(),
		})
	}
}

// RenewalDAPayload is the JSON carrier for the responsible party's re-signed DA
// (SignRenewalDA output → management API).
type RenewalDAPayload struct {
	ReasonCode         string `json:"reason_code"`
	ReasonDesc         string `json:"reason_description,omitempty"`
	RequestedLifetime  int    `json:"requested_lifetime"`
	Timestamp          string `json:"timestamp"`
	Nonce              []byte `json:"nonce"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SignatureValue     []byte `json:"signature_value"`
}

// toDelegationAuthorization converts the JSON carrier to DelegationAuthorization.
func (p RenewalDAPayload) toDelegationAuthorization() (DelegationAuthorization, error) {
	da := DelegationAuthorization{
		Reason:            Reason{ReasonCode: p.ReasonCode, Description: p.ReasonDesc},
		RequestedLifetime: p.RequestedLifetime,
		Nonce:             p.Nonce,
		SignatureValue:    p.SignatureValue,
	}
	if p.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339Nano, p.Timestamp)
		if err != nil {
			return da, fmt.Errorf("timestamp must be RFC3339: %v", err)
		}
		da.Timestamp = ts
	}
	if p.SignatureAlgorithm != "" {
		da.SignatureAlgorithm.Algorithm = parseOIDString(p.SignatureAlgorithm)
		if len(da.SignatureAlgorithm.Algorithm) == 0 {
			return da, fmt.Errorf("invalid signature algorithm OID %q", p.SignatureAlgorithm)
		}
	}
	return da, nil
}

func parseOIDString(s string) asn1.ObjectIdentifier {
	oid, err := parseOID(s)
	if err != nil {
		return nil
	}
	return oid
}

// parseOID parses a dotted-decimal OID string.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID component %q", p)
		}
		oid[i] = n
	}
	return oid, nil
}
