// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// goodReloadConfig is a fully valid configuration used as the running
// baseline during the reload tests. The file-based path is covered separately
// by TestConfigStoreReloadFileResolvesRelativePaths.
const goodReloadConfig = `
follow_redirects: true
enable_http2: true
http_headers:
  X-Custom-Header:
    values: [good-value]
`

// mixedReloadConfig keeps a valid first item but adds an invalid second item
// (a reserved header). Item-by-item application would install the valid
// header before failing; atomic reload must reject the whole document.
const mixedReloadConfig = `
follow_redirects: true
enable_http2: true
http_headers:
  X-Custom-Header:
    values: [should-never-apply]
  User-Agent:
    values: [forbidden]
`

// multipleBadItemsConfig contains two invalid reserved headers so the error
// reporting can be checked for more than one offending location.
const multipleBadItemsConfig = `
http_headers:
  Host:
    values: [forbidden-host]
  Authorization:
    values: [forbidden-authz]
`

// structurallyInvalidConfig is not valid YAML for the target type: a string
// is given where a boolean is expected. The error must carry the source line.
const structurallyInvalidConfig = `
follow_redirects: "not-a-bool"
http_headers:
  X-Custom-Header:
    values: [good-value]
`

// conflictingFieldsConfig fails the cross-field validation of
// HTTPClientConfig: bearer_token and bearer_token_file are mutually exclusive.
const conflictingFieldsConfig = `
bearer_token: abc
bearer_token_file: testdata/bearer.token
`

func newTestStore(t *testing.T) *ConfigStore {
	t.Helper()
	cfg, err := LoadHTTPConfig(goodReloadConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return NewConfigStore(cfg)
}

// fieldPathErrors walks the (possibly joined) error tree and collects every
// FieldPathError, mirroring how operators inspect a failed reload report.
func fieldPathErrors(err error) []*FieldPathError {
	var out []*FieldPathError
	if err == nil {
		return out
	}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, child := range joined.Unwrap() {
			out = append(out, fieldPathErrors(child)...)
		}
		return out
	}
	if fieldErr, ok := err.(*FieldPathError); ok {
		out = append(out, fieldErr)
	}
	return out
}

func requireFieldPath(t *testing.T, err error, wantPath, wantMessage string) *FieldPathError {
	t.Helper()
	for _, fieldErr := range fieldPathErrors(err) {
		if fieldErr.Path == wantPath && strings.Contains(fieldErr.Error(), wantMessage) {
			return fieldErr
		}
	}
	require.Failf(t, "field path error not found",
		"wanted path %q containing %q; got errors: %v", wantPath, wantMessage, fieldPathErrors(err))
	return nil
}

func headerFromConfig(t *testing.T, cfg *HTTPClientConfig, server *httptest.Server) string {
	t.Helper()
	client, err := NewClientFromConfig(*cfg, "reload-test")
	require.NoError(t, err)
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", strings.TrimSpace(string(body)))
	return resp.Header.Get("X-Received-Custom")
}

// TestConfigStoreRejectsInvalidReloadAtomically is the main regression test:
// a reload whose document mixes valid and invalid items must not change the
// running configuration at all. The service keeps behaving exactly as before
// the reload attempt.
func TestConfigStoreRejectsInvalidReloadAtomically(t *testing.T) {
	store := newTestStore(t)
	before := store.Current()

	var received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Custom-Header")
		w.Header().Set("X-Received-Custom", received)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(server.Close)

	// Baseline: the running configuration injects the good header.
	require.Equal(t, "good-value", headerFromConfig(t, before, server))

	err := store.Reload([]byte(mixedReloadConfig))
	require.Error(t, err)

	// The error points at the exact offending item.
	fieldErr := requireFieldPath(t, err, "http_headers.User-Agent",
		`setting header "User-Agent" is not allowed`)
	require.Zero(t, fieldErr.Line)

	// All-or-nothing: the active configuration is still the previous one.
	after := store.Current()
	require.Same(t, before, after, "the running configuration must not be replaced on failed reload")
	require.Equal(t, "good-value", headerFromConfig(t, after, server))
	require.NotContains(t, after.HTTPHeaders.Headers, "User-Agent")

	// And the rejected candidate's valid item must not have leaked in.
	require.Equal(t, []string{"good-value"}, after.HTTPHeaders.Headers["X-Custom-Header"].Values)
}

// TestConfigStoreReportsEveryOffendingLocation ensures validation collects
// all bad items in a single reload attempt instead of stopping at the first.
func TestConfigStoreReportsEveryOffendingLocation(t *testing.T) {
	store := newTestStore(t)

	err := store.Reload([]byte(multipleBadItemsConfig))
	require.Error(t, err)
	requireFieldPath(t, err, "http_headers.Host", `setting header "Host" is not allowed`)
	requireFieldPath(t, err, "http_headers.Authorization",
		`setting header "Authorization" is not allowed`)
	require.Len(t, fieldPathErrors(err), 2, "both offending items must be reported at once")

	// The good configuration remains active and usable.
	require.NotNil(t, store.Current().HTTPHeaders)
}

// TestConfigStoreStructuralErrorKeepsLineNumber checks that YAML parsing
// failures still report the source line and never touch the running config.
func TestConfigStoreStructuralErrorKeepsLineNumber(t *testing.T) {
	store := newTestStore(t)
	before := store.Current()

	err := store.Reload([]byte(structurallyInvalidConfig))
	require.Error(t, err)

	fieldErrs := fieldPathErrors(err)
	require.NotEmpty(t, fieldErrs)
	require.Equal(t, 2, fieldErrs[0].Line, "error should locate follow_redirects on line 2")
	require.Contains(t, fieldErrs[0].Error(), "line 2")

	require.Same(t, before, store.Current())
}

// TestConfigStoreCrossFieldValidationError covers semantic validation that
// only HTTPClientConfig.Validate performs, and labels it as a root-level item.
func TestConfigStoreCrossFieldValidationError(t *testing.T) {
	store := newTestStore(t)
	before := store.Current()

	err := store.Reload([]byte(conflictingFieldsConfig))
	require.Error(t, err)
	requireFieldPath(t, err, "<root>",
		"at most one of bearer_token & bearer_token_file must be configured")
	require.Same(t, before, store.Current())
}

// TestConfigStoreValidReloadSwapsAtomically verifies the happy path: a fully
// valid document is applied, and afterwards the new behavior is observable.
func TestConfigStoreValidReloadSwapsAtomically(t *testing.T) {
	store := newTestStore(t)
	before := store.Current()

	const validReloadConfig = `
follow_redirects: true
enable_http2: true
http_headers:
  X-Custom-Header:
    values: [new-value]
  X-Another-Header:
    values: [another-value]
`
	require.NoError(t, store.Reload([]byte(validReloadConfig)))

	after := store.Current()
	require.NotSame(t, before, after)
	require.Equal(t, []string{"new-value"}, after.HTTPHeaders.Headers["X-Custom-Header"].Values)
	require.Equal(t, []string{"another-value"}, after.HTTPHeaders.Headers["X-Another-Header"].Values)
}

// TestConfigStoreReloadDoesNotInterruptReaders runs continuous readers while
// reloads (valid and invalid) happen. Every read must observe a complete,
// usable configuration and never an error or a mixed state.
func TestConfigStoreReloadDoesNotInterruptReaders(t *testing.T) {
	store := newTestStore(t)

	var observedHeader atomic.Value
	observedHeader.Store("good-value")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("X-Custom-Header")
		observedHeader.Store(value)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(server.Close)

	const validReloadConfig = `
follow_redirects: true
enable_http2: true
http_headers:
  X-Custom-Header:
    values: [new-value]
`

	var readers sync.WaitGroup
	stop := make(chan struct{})
	var readFailures atomic.Int64

	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cfg := store.Current()
				client, err := NewClientFromConfig(*cfg, "concurrent-reader")
				if err != nil {
					readFailures.Add(1)
					continue
				}
				resp, err := client.Get(server.URL)
				if err != nil {
					readFailures.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}

	var reloaders sync.WaitGroup
	for seed := range 4 {
		reloaders.Add(1)
		go func(seed int) {
			defer reloaders.Done()
			for range 25 {
				if seed%2 == 0 {
					_ = store.Reload([]byte(mixedReloadConfig)) // always rejected
				} else {
					_ = store.Reload([]byte(validReloadConfig)) // always applied
				}
			}
		}(seed)
	}
	reloaders.Wait()
	close(stop)
	readers.Wait()

	require.Zero(t, readFailures.Load(), "no reader must ever see a broken or half-applied configuration")

	// Only the two complete configurations may ever be observed, never a
	// mixture of their header values.
	value := observedHeader.Load().(string)
	require.Contains(t, []string{"good-value", "new-value"}, value)
}

// TestConfigStoreReloadFileResolvesRelativePaths mirrors
// TestLoadHTTPConfigFileResolvesPathsRelativeToConfigFile: a successful file
// reload anchors relative paths at the configuration file's directory, while
// an invalid file leaves the running configuration untouched.
func TestConfigStoreReloadFileResolvesRelativePaths(t *testing.T) {
	store := newTestStore(t)
	before := store.Current()

	dir := t.TempDir()
	goodFile := filepath.Join(dir, "good.yaml")
	require.NoError(t, os.WriteFile(goodFile, []byte(`
http_headers:
  X-Custom-Header:
    files: [headers-file]
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "headers-file"), []byte("from-file"), 0o600))

	require.NoError(t, store.ReloadFile(goodFile))
	header := store.Current().HTTPHeaders.Headers["X-Custom-Header"]
	require.Equal(t, filepath.Join(dir, "headers-file"), header.Files[0])

	badFile := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badFile, []byte(mixedReloadConfig), 0o600))
	err := store.ReloadFile(badFile)
	require.Error(t, err)
	requireFieldPath(t, err, "http_headers.User-Agent",
		`setting header "User-Agent" is not allowed`)
	require.NotSame(t, before, store.Current(), "the good file reload should have replaced the initial config")
	require.Equal(t, filepath.Join(dir, "headers-file"),
		store.Current().HTTPHeaders.Headers["X-Custom-Header"].Files[0])
}

// TestFieldPathErrorUnwrap ensures location metadata does not hide the
// original validation error from errors.Is/errors.As consumers.
func TestFieldPathErrorUnwrap(t *testing.T) {
	original := errors.New("setting header \"X\" is not allowed")
	wrapped := atPath("http_headers.X", original)
	require.True(t, errors.Is(wrapped, original))

	var fieldErr *FieldPathError
	require.True(t, errors.As(wrapped, &fieldErr))
	require.Equal(t, "http_headers.X", fieldErr.Path)
	require.Equal(t, "http_headers.X: setting header \"X\" is not allowed", wrapped.Error())
}

func TestSplitYAMLLine(t *testing.T) {
	line, msg := splitYAMLLine("line 7: cannot unmarshal !!str into bool")
	require.Equal(t, 7, line)
	require.Equal(t, "cannot unmarshal !!str into bool", msg)

	line, msg = splitYAMLLine("some plain error")
	require.Zero(t, line)
	require.Equal(t, "some plain error", msg)
}

// TestConfigStoreRejectsAllKnownBadConfigs replays every invalid
// configuration already covered by TestInvalidHTTPConfigs through the atomic
// reload path: each one must be rejected with its known error message while
// the previously running configuration stays in place.
func TestConfigStoreRejectsAllKnownBadConfigs(t *testing.T) {
	for _, ee := range invalidHTTPClientConfigs {
		t.Run(ee.httpClientConfigFile, func(t *testing.T) {
			content, err := os.ReadFile(ee.httpClientConfigFile)
			require.NoError(t, err)

			store := newTestStore(t)
			before := store.Current()

			err = store.Reload(content)
			require.Error(t, err)
			require.Contains(t, err.Error(), ee.errMsg)
			require.Same(t, before, store.Current(),
				"the running configuration must survive a failed reload")
		})
	}
}
