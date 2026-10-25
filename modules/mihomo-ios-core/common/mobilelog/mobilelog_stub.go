//go:build !ios || !with_gvisor

package mobilelog

func Native(level string, message string) {}

func ShouldEmit(level string) bool { return false }
