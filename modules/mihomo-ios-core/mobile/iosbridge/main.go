package main

/*
#include <stdlib.h>
extern void MihomoIOSNativeLog(const char *level, const char *message);
*/
import "C"

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"

	"github.com/Dreamacro/clash/common/mobilephase"
	"github.com/Dreamacro/clash/config"
	CN "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/hub/route"
)

type runtimeState struct {
	mu               sync.Mutex
	running          bool
	homeDir          string
	configPath       string
	controllerAddr   string
	controllerSecret string
}

var state runtimeState

const mobileGoMemoryBudget = 24 * 1024 * 1024

func init() {
	if runtime.GOOS == "ios" {
		debug.SetMemoryLimit(mobileGoMemoryBudget)
	}
}

const (
	configValidationTimeout = 2 * time.Second
	coreBootstrapTimeout    = 8 * time.Second
	controllerWarmupTimeout = 3 * time.Second
)

//export MihomoStart
func MihomoStart(configPath *C.char, homeDir *C.char, controllerAddr *C.char, controllerSecret *C.char) *C.char {
	logNative("info", "Go bridge entered MihomoStart.")
	cfgPath := C.GoString(configPath)
	root := C.GoString(homeDir)
	addr := C.GoString(controllerAddr)
	secret := C.GoString(controllerSecret)

	if cfgPath == "" {
		return errorCString("config path is empty")
	}
	if root == "" {
		return errorCString("home dir is empty")
	}
	state.mu.Lock()
	if state.running {
		if cfgPath == state.configPath && root == state.homeDir {
			state.mu.Unlock()
			return nil
		}
		stopLocked()
	}
	state.mu.Unlock()

	mobilephase.Reset(true)
	mobilephase.SetPhase("validatingConfig", "Validating runtime configuration.")
	CN.SetHomeDir(root)
	CN.SetConfig(cfgPath)
	logNative("info", "Go bridge is calling config.Init for the embedded core.")

	if err := runWithTimeout(configValidationTimeout, func() error {
		return config.Init(CN.Path.HomeDir())
	}); err != nil {
		mobilephase.MarkFailure("validatingConfig", err.Error())
		logNative("error", fmt.Sprintf("config.Init failed: %s", err.Error()))
		return errorCString(err.Error())
	}
	logNative("info", "config.Init completed successfully.")

	mobilephase.SetPhase("startingCore", "Bootstrapping embedded Mihomo core.")
	parseResult := make(chan error, 1)
	go func() {
		logNative("info", "Go bridge entered the hub.Parse goroutine.")
		mobilephase.SetPhase("startingCore", "Calling hub.Parse on the embedded Mihomo core.")
		err := hub.Parse(
			hub.WithExternalController(addr),
			hub.WithSecret(secret),
		)
		if err != nil {
			logNative("error", fmt.Sprintf("hub.Parse returned an error: %s", err.Error()))
		} else {
			logNative("info", "hub.Parse returned without an error.")
		}
		parseResult <- err
	}()

	mobilephase.SetPhase("startingCore", "Waiting for the critical runtime path to become ready.")
	logNative("info", "Waiting for the critical runtime path to become ready.")
	if err := waitForCriticalReady(parseResult, coreBootstrapTimeout); err != nil {
		mobilephase.MarkFailure(currentFailurePhase(), err.Error())
		logNative("error", fmt.Sprintf("Critical runtime path failed: %s", err.Error()))
		state.mu.Lock()
		stopLocked()
		state.mu.Unlock()
		return errorCString(err.Error())
	}

	state.mu.Lock()
	state.running = true
	state.homeDir = root
	state.configPath = cfgPath
	state.controllerAddr = addr
	state.controllerSecret = secret
	state.mu.Unlock()

	if addr != "" {
		go monitorControllerWarmup(parseResult, controllerWarmupTimeout)
		go logNative("info", "Go bridge completed MihomoStart successfully and returned with the requested controller address.")
	} else {
		go logNative("info", "Go bridge completed MihomoStart successfully with the embedded controller disabled for iOS startup isolation.")
	}
	return nil
}

//export MihomoStop
func MihomoStop() *C.char {
	state.mu.Lock()
	defer state.mu.Unlock()

	stopLocked()
	mobilephase.Reset(false)
	return nil
}

//export MihomoReload
func MihomoReload() *C.char {
	state.mu.Lock()
	defer state.mu.Unlock()

	if !state.running {
		return errorCString("runtime is not running")
	}

	CN.SetHomeDir(state.homeDir)
	CN.SetConfig(state.configPath)

	cfg, err := executor.Parse()
	if err != nil {
		mobilephase.MarkFailure("validatingConfig", err.Error())
		return errorCString(err.Error())
	}

	mobilephase.SetPhase("applyingConfig", "Reloading runtime configuration.")
	executor.ApplyConfig(cfg, true)
	return nil
}

//export MihomoVersion
func MihomoVersion() *C.char {
	return C.CString(CN.Version)
}

//export MihomoControllerAddress
func MihomoControllerAddress() *C.char {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.controllerAddr == "" {
		return nil
	}
	return C.CString(state.controllerAddr)
}

//export MihomoStartupPhase
func MihomoStartupPhase() *C.char {
	return C.CString(mobilephase.SnapshotValue().Phase)
}

//export MihomoStartupMessage
func MihomoStartupMessage() *C.char {
	return C.CString(mobilephase.SnapshotValue().Message)
}

//export MihomoLastStartupError
func MihomoLastStartupError() *C.char {
	return C.CString(mobilephase.SnapshotValue().LastError)
}

//export MihomoIsRunning
func MihomoIsRunning() C.int {
	state.mu.Lock()
	running := state.running
	state.mu.Unlock()

	if running || mobilephase.SnapshotValue().CriticalReady {
		return 1
	}
	return 0
}

func main() {}

func logNative(level string, message string) {
	cl := C.CString(level)
	cm := C.CString(message)
	defer func() {
		C.free(unsafe.Pointer(cl))
		C.free(unsafe.Pointer(cm))
	}()
	C.MihomoIOSNativeLog(cl, cm)
}

func stopLocked() {
	if !state.running {
		route.Stop()
		return
	}
	executor.Shutdown()
	route.Stop()
	state.running = false
	state.homeDir = ""
	state.configPath = ""
	state.controllerAddr = ""
	state.controllerSecret = ""
}

func waitForCriticalReady(parseResult <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := mobilephase.SnapshotValue()
		if snapshot.CriticalReady {
			return nil
		}
		if snapshot.LastError != "" {
			return fmt.Errorf("%s", snapshot.LastError)
		}

		if err := drainParseResult(parseResult); err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}

	snapshot := mobilephase.SnapshotValue()
	phase := snapshot.Phase
	if phase == "" {
		phase = "startingCore"
	}
	return fmt.Errorf("runtime startup timed out while %s", phase)
}

func waitForControllerAddress(parseResult <-chan error, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := drainParseResult(parseResult); err != nil {
			return "", err
		}
		if addr := route.ServerAddress(); addr != "" {
			return addr, nil
		}
		snapshot := mobilephase.SnapshotValue()
		if snapshot.LastError != "" {
			return "", fmt.Errorf("%s", snapshot.LastError)
		}
		time.Sleep(25 * time.Millisecond)
	}
	return "", fmt.Errorf("controller did not publish a listening address before timeout")
}

func monitorControllerWarmup(parseResult <-chan error, timeout time.Duration) {
	logNative("info", "Background controller warmup monitor started.")
	actualAddr, err := waitForControllerAddress(parseResult, timeout)
	if err != nil {
		logNative("warn", fmt.Sprintf("Background controller warmup did not publish a controller address before timeout: %s", err.Error()))
		return
	}

	state.mu.Lock()
	if state.running {
		state.controllerAddr = actualAddr
	}
	state.mu.Unlock()

	logNative("info", fmt.Sprintf("Background controller warmup confirmed controller address %s.", actualAddr))
}

func drainParseResult(parseResult <-chan error) error {
	select {
	case err := <-parseResult:
		return err
	default:
		return nil
	}
}

func runWithTimeout(timeout time.Duration, operation func() error) error {
	result := make(chan error, 1)
	go func() {
		result <- operation()
	}()

	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("operation timed out after %s", timeout)
	}
}

func currentFailurePhase() string {
	snapshot := mobilephase.SnapshotValue()
	if snapshot.Phase == "" || snapshot.Phase == "failed" {
		if snapshot.LastFailurePhase != "" {
			return snapshot.LastFailurePhase
		}
		return "startingCore"
	}
	return snapshot.Phase
}

func errorCString(message string) *C.char {
	return C.CString(message)
}
