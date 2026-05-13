package behavior

import (
	"testing"
)

// --- ProcTree tests ---

func TestProcTree_AddRoot(t *testing.T) {
	tr := NewProcTree()
	tr.AddRoot(1000)
	if !tr.Contains(1000) {
		t.Error("root PID should be in tree")
	}
	if tr.Contains(9999) {
		t.Error("unregistered PID should not be in tree")
	}
}

func TestProcTree_AddChild(t *testing.T) {
	tr := NewProcTree()
	tr.AddRoot(1000)

	// Child of tracked root → added
	if !tr.AddChild(2000, 1000) {
		t.Error("child of root should be added")
	}
	if !tr.Contains(2000) {
		t.Error("added child should be in tree")
	}

	// Child of untracked process → rejected
	if tr.AddChild(3000, 9999) {
		t.Error("child of untracked pid should be rejected")
	}
	if tr.Contains(3000) {
		t.Error("rejected child should not be in tree")
	}
}

func TestProcTree_TransitiveClosure(t *testing.T) {
	tr := NewProcTree()
	tr.AddRoot(100)
	tr.AddChild(200, 100) // grandchild of root
	tr.AddChild(300, 200) // great-grandchild

	if !tr.Contains(300) {
		t.Error("great-grandchild should be tracked transitively")
	}
}

func TestProcTree_Len(t *testing.T) {
	tr := NewProcTree()
	if tr.Len() != 0 {
		t.Errorf("empty tree should have Len=0, got %d", tr.Len())
	}
	tr.AddRoot(100)
	tr.AddRoot(200)
	if tr.Len() != 2 {
		t.Errorf("expected Len=2, got %d", tr.Len())
	}
}

// --- SelectBackend tests ---

func TestSelectBackend_Off(t *testing.T) {
	tr := NewProcTree()
	b, active := SelectBackend("off", tr, nil)
	if active {
		t.Error("'off' backend should not be active")
	}
	if b.Name() != "off" {
		t.Errorf("expected name 'off', got %q", b.Name())
	}
}

func TestSelectBackend_UnknownName(t *testing.T) {
	tr := NewProcTree()
	b, active := SelectBackend("nonexistent", tr, nil)
	if active {
		t.Error("unknown backend should not be active")
	}
	_ = b
}

func TestNoopBackend(t *testing.T) {
	b := &noopBackend{name: "test"}
	if b.Available() {
		t.Error("noopBackend.Available() should return false")
	}
	ch, err := b.Start(nil)
	if err != nil {
		t.Errorf("noopBackend.Start: unexpected error: %v", err)
	}
	// Channel should be closed immediately.
	_, open := <-ch
	if open {
		t.Error("noopBackend channel should be closed")
	}
}
