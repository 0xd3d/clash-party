package mobilephase

import (
	"sync"
	"time"
)

type Snapshot struct {
	Phase            string
	Message          string
	LastError        string
	LastFailurePhase string
	Running          bool
	CriticalReady    bool
	FastStartup      bool
	UpdatedAt        time.Time
}

var state struct {
	mu       sync.Mutex
	snapshot Snapshot
}

func Reset(fastStartup bool) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.snapshot = Snapshot{
		Phase:       "idle",
		Message:     "Runtime is idle.",
		FastStartup: fastStartup,
		UpdatedAt:   time.Now(),
	}
}

func SnapshotValue() Snapshot {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.snapshot
}

func FastStartupEnabled() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.snapshot.FastStartup
}

func SetPhase(phase string, message string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.snapshot.Phase = phase
	state.snapshot.Message = message
	state.snapshot.UpdatedAt = time.Now()
}

func MarkFailure(phase string, message string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.snapshot.Phase = "failed"
	state.snapshot.Message = message
	state.snapshot.LastError = message
	state.snapshot.LastFailurePhase = phase
	state.snapshot.Running = false
	state.snapshot.CriticalReady = false
	state.snapshot.UpdatedAt = time.Now()
}

func MarkCriticalReady(message string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.snapshot.CriticalReady = true
	state.snapshot.Phase = "warmingProviders"
	state.snapshot.Message = message
	state.snapshot.UpdatedAt = time.Now()
}

func MarkRunning(message string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.snapshot.Running = true
	state.snapshot.CriticalReady = true
	state.snapshot.Phase = "running"
	state.snapshot.Message = message
	state.snapshot.UpdatedAt = time.Now()
}
