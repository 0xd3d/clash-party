package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Dreamacro/clash/listener/inner"
)

// An iOS Network Extension's own sockets are outside packetFlow. Resource
// updates must therefore enter the existing core rules, not http.DefaultClient.
// This source-build baseline is not exposed as a user policy option.
var RequireRuleResourceDownloads = runtime.GOOS == "ios"

type resourceBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *resourceBody) Close() error { defer body.cancel(); return body.ReadCloser.Close() }

func GetResource(url string) (*http.Response, error) {
	if !RequireRuleResourceDownloads {
		return http.Get(url)
	}
	if !inner.IsReady() {
		return nil, fmt.Errorf("core rules are not ready; iOS requires a bundled or cached resource before startup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	response, err := HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		cancel()
		return nil, fmt.Errorf("resource update returned HTTP %d", response.StatusCode)
	}
	response.Body = &resourceBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

// Write only a complete successful response. A failed request/body never
// truncates an existing cache, and startup never falls back to a direct client.
func DownloadResource(url, path string) error {
	response, err := GetResource(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	file, err := os.CreateTemp(filepath.Dir(path), ".geo-resource-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err = io.Copy(file, response.Body); err != nil {
		return err
	}
	if err = file.Chmod(0644); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
