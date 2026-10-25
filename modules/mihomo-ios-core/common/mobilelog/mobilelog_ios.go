//go:build ios && with_gvisor

package mobilelog

/*
#include <stdlib.h>
extern void MihomoIOSNativeLog(const char *level, const char *message);
*/
import "C"

import (
	"os"
	"strings"
	"unsafe"
)

func Native(level string, message string) {
	if !ShouldEmit(level) {
		return
	}
	cl := C.CString(level)
	cm := C.CString(message)
	defer func() {
		C.free(unsafe.Pointer(cl))
		C.free(unsafe.Pointer(cm))
	}()
	C.MihomoIOSNativeLog(cl, cm)
}

func ShouldEmit(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "trace":
		return debugEnabled()
	default:
		return true
	}
}

func debugEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("MIHOMO_IOS_NATIVE_DEBUG")))
	return value == "1" || value == "true" || value == "yes" || value == "debug"
}
