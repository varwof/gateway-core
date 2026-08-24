package gw

import (
	"sync"
	"testing"
	"time"
)

func TestTaskRegistryRegisterCompleteUnregister(t *testing.T) {
	reg := NewTaskRegistry()
	now := time.Now().Unix()

	prev := reg.Register("task-1", "ABCD", "agent-1", "batch", now)
	if prev != nil {
		t.Fatalf("expected nil prev, got %+v", prev)
	}
	if reg.Len() != 1 {
		t.Fatalf("expected 1 task, got %d", reg.Len())
	}
	rec := reg.Lookup("task-1")
	if rec == nil || rec.Serial != "ABCD" || rec.Status != TaskActive {
		t.Fatalf("unexpected record: %+v", rec)
	}

	done := reg.Complete("task-1", now+1)
	if done == nil || done.Status != TaskCompleted {
		t.Fatalf("expected completed record, got %+v", done)
	}

	rec2 := reg.Unregister("task-1")
	if rec2 == nil || rec2.Status != TaskCompleted {
		t.Fatalf("expected unregistered record, got %+v", rec2)
	}
	if reg.Len() != 0 {
		t.Fatalf("expected 0 tasks after unregister, got %d", reg.Len())
	}

	if got := reg.Complete("missing", now); got != nil {
		t.Fatalf("expected nil for missing task, got %+v", got)
	}
	if got := reg.Lookup("missing"); got != nil {
		t.Fatalf("expected nil lookup, got %+v", got)
	}
}

func TestTaskRegistryOverwriteAndList(t *testing.T) {
	reg := NewTaskRegistry()
	now := time.Now().Unix()
	reg.Register("t1", "1111", "a1", "", now)
	reg.Register("t2", "2222", "a2", "", now)

	prev := reg.Register("t1", "3333", "a1", "overwritten", now+1)
	if prev == nil || prev.Serial != "1111" {
		t.Fatalf("expected old record returned, got %+v", prev)
	}
	if rec := reg.Lookup("t1"); rec.Serial != "3333" {
		t.Fatalf("expected overwritten serial, got %+v", rec)
	}

	all := reg.List()
	if len(all) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(all))
	}
}

func TestTaskRegistryConcurrent(t *testing.T) {
	reg := NewTaskRegistry()
	now := time.Now().Unix()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "t"
			reg.Register(id, "s", "a", "", now)
			reg.Complete(id, now+1)
			reg.Unregister(id)
		}(i)
	}
	wg.Wait()
	if reg.Len() != 0 {
		t.Fatalf("expected 0 tasks after concurrent churn, got %d", reg.Len())
	}
}

func TestTaskCompletedFromHeader(t *testing.T) {
	// completed + explicit task id
	id, done := TaskCompletedFromHeader(func(k string) string {
		switch k {
		case HeaderTaskID:
			return "task-9"
		case HeaderTaskStatus:
			return CompletedHeaderValue
		}
		return ""
	}, "fallback")
	if !done || id != "task-9" {
		t.Fatalf("expected (task-9, true), got (%q, %v)", id, done)
	}

	// completed + no task id → fallback
	id, done = TaskCompletedFromHeader(func(k string) string {
		if k == HeaderTaskStatus {
			return CompletedHeaderValue
		}
		return ""
	}, "cn-agent")
	if !done || id != "cn-agent" {
		t.Fatalf("expected (cn-agent, true), got (%q, %v)", id, done)
	}

	// no signal
	id, done = TaskCompletedFromHeader(func(k string) string { return "" }, "x")
	if done {
		t.Fatalf("expected not done, got %q", id)
	}

	// nil header fn
	if _, done := TaskCompletedFromHeader(nil, "x"); done {
		t.Fatal("expected not done for nil header fn")
	}
}

func TestTaskRegistryNilSafety(t *testing.T) {
	var reg *TaskRegistry
	if reg.Register("x", "s", "a", "", 1) != nil {
		t.Fatal("expected nil register on nil registry")
	}
	if reg.Complete("x", 1) != nil {
		t.Fatal("expected nil complete on nil registry")
	}
	if reg.Unregister("x") != nil {
		t.Fatal("expected nil unregister on nil registry")
	}
	if reg.Lookup("x") != nil {
		t.Fatal("expected nil lookup on nil registry")
	}
	if reg.Len() != 0 {
		t.Fatal("expected 0 len on nil registry")
	}
	if len(reg.List()) != 0 {
		t.Fatal("expected empty list on nil registry")
	}
}
