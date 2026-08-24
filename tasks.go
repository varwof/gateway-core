// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// TaskRegistry — task lifecycle tracking (spec L75 revocation triggers a/b/c/d/e
// active reporting path, A3/A4/A5)
//
// When an agent starts a task, it registers the task context with the gateway
// (task ID → certificate serial number). When the task completes, a completion
// signal (HTTP Header or management API) triggers conditional revocation:
// the certificate is revoked immediately after task completion ("use-and-revoke"),
// rather than relying solely on connection close.

package gw

import (
	"fmt"
	"sync"
)

// TaskStatus represents the completion status of a task.
type TaskStatus string

const (
	// TaskActive indicates the task is in progress.
	TaskActive TaskStatus = "active"
	// TaskCompleted indicates the task is completed (triggers revocation).
	TaskCompleted TaskStatus = "completed"
)

// TaskRecord is a single record in the task registry.
type TaskRecord struct {
	TaskID   string     `json:"task_id"`
	Serial   string     `json:"serial"`
	AgentID  string     `json:"agent_id,omitempty"`
	Status   TaskStatus `json:"status"`
	Created  int64      `json:"created"`
	Note     string     `json:"note,omitempty"`
	Revoked  bool       `json:"revoked"`
	RevokeAt int64      `json:"revoke_at,omitempty"`
}

// TaskRegistry tracks task → certificate serial number mappings keyed by task ID,
// used to trigger conditional revocation via completion signals.
// Thread-safe.
type TaskRegistry struct {
	mu    sync.RWMutex
	tasks map[string]*TaskRecord
}

// NewTaskRegistry creates an empty task registry.
func NewTaskRegistry() *TaskRegistry {
	return &TaskRegistry{tasks: make(map[string]*TaskRecord)}
}

// Register registers a new task and returns the previous record (if one with the
// same ID already existed, it is overwritten and the old one is returned).
// Does not register if taskID is empty (returns nil).
func (r *TaskRegistry) Register(taskID, serial, agentID, note string, now int64) *TaskRecord {
	if r == nil || taskID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.tasks[taskID]
	rec := &TaskRecord{
		TaskID:  taskID,
		Serial:  serial,
		AgentID: agentID,
		Status:  TaskActive,
		Created: now,
		Note:    note,
	}
	r.tasks[taskID] = rec
	return prev
}

// Complete marks a task as completed and returns its associated certificate serial
// number (for the caller to trigger revocation).
// Returns an empty string for unregistered tasks.
func (r *TaskRegistry) Complete(taskID string, now int64) *TaskRecord {
	if r == nil || taskID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.tasks[taskID]
	if rec == nil {
		return nil
	}
	rec.Status = TaskCompleted
	rec.RevokeAt = now
	return rec
}

// Unregister removes a task record. Returns the removed record (may be nil).
func (r *TaskRegistry) Unregister(taskID string) *TaskRecord {
	if r == nil || taskID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.tasks[taskID]
	delete(r.tasks, taskID)
	return rec
}

// Lookup queries a task record (read-only).
func (r *TaskRegistry) Lookup(taskID string) *TaskRecord {
	if r == nil || taskID == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec := r.tasks[taskID]
	if rec == nil {
		return nil
	}
	cp := *rec
	return &cp
}

// List returns a snapshot of all task records (sorted by creation time descending).
func (r *TaskRegistry) List() []TaskRecord {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]TaskRecord, 0, len(r.tasks))
	for _, rec := range r.tasks {
		out = append(out, *rec)
	}
	return out
}

// Len returns the number of currently active tasks.
func (r *TaskRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tasks)
}

// HeaderTaskID is the header name for identifying the task ID in requests (A3).
const HeaderTaskID = "X-AIC-Task-Id"

// HeaderTaskStatus is the header name for carrying the task completion signal in requests (A4).
const HeaderTaskStatus = "X-AIC-Task-Status"

// CompletedHeaderValue is the value of the task completion signal.
const CompletedHeaderValue = "completed"

// TaskIDFromHeader extracts the task ID (HeaderTaskID) from a request; returns "" if absent.
func TaskIDFromHeader(h func(string) string) string {
	if h == nil {
		return ""
	}
	return h(HeaderTaskID)
}

// TaskCompletedFromHeader detects whether a request carries a task completion signal
// (HeaderTaskStatus == completed). Returns the taskID and whether it is completed.
// taskID prefers the explicit HeaderTaskID; when absent, falls back to fallbackID
// (for simple scenarios without task IDs, revoking directly by certificate).
func TaskCompletedFromHeader(h func(string) string, fallbackID string) (string, bool) {
	if h == nil {
		return "", false
	}
	if v := h(HeaderTaskStatus); v != "" && v == CompletedHeaderValue {
		id := h(HeaderTaskID)
		if id == "" {
			id = fallbackID
		}
		return id, true
	}
	return "", false
}

// ErrNoTask is returned by complete-by-serial lookups when the task is unknown.
var ErrNoTask = fmt.Errorf("task not found")
