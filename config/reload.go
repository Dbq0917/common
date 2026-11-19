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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.yaml.in/yaml/v2"
)

// FieldPathError wraps a validation or parsing error with the location of
// the offending configuration item. The location is expressed both as a
// dotted configuration path (e.g. "http_headers.User-Agent") and, when
// available, as the 1-based line number in the source YAML document.
//
// FieldPathError values are returned joined together by errors.Join when a
// configuration document contains more than one invalid item, so every
// offending location can be reported from a single reload attempt instead of
// failing on the first one.
type FieldPathError struct {
	// Path is the dotted configuration path of the invalid item, relative
	// to the root of the configuration document.
	Path string
	// Line is the 1-based line number in the source YAML document, or 0
	// when the error cannot be attributed to a particular line.
	Line int
	// Err is the underlying validation or parsing error.
	Err error
}

// Error implements the error interface.
func (e *FieldPathError) Error() string {
	var b strings.Builder
	if e.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", e.Line)
	}
	if e.Path != "" {
		fmt.Fprintf(&b, "%s: ", e.Path)
	}
	b.WriteString(e.Err.Error())
	return b.String()
}

// Unwrap returns the wrapped error so that errors.Is and errors.As keep
// working on the original validation errors.
func (e *FieldPathError) Unwrap() error {
	return e.Err
}

// atPath wraps err with a configuration path. A nil error is returned as-is,
// and an existing FieldPathError is re-parented instead of being wrapped a
// second time.
func atPath(path string, err error) error {
	if err == nil {
		return nil
	}
	var fieldErr *FieldPathError
	if errors.As(err, &fieldErr) {
		return &FieldPathError{
			Path: joinPath(path, fieldErr.Path),
			Line: fieldErr.Line,
			Err:  fieldErr.Err,
		}
	}
	return &FieldPathError{Path: path, Err: err}
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + "." + child
}

// validateHTTPClientConfig validates every independently checkable section of
// an HTTPClientConfig and returns the joined FieldPathError values for all of
// the offending items.
//
// The receiver is never mutated: the normalization performed by
// HTTPClientConfig.Validate is applied to a copy so that a failed reload
// cannot leave partially rewritten state behind.
func validateHTTPClientConfig(cfg *HTTPClientConfig) error {
	var errs []error

	if err := cfg.TLSConfig.Validate(); err != nil {
		errs = append(errs, atPath("tls_config", err))
	}
	if err := cfg.ProxyConfig.Validate(); err != nil {
		errs = append(errs, atPath("proxy_config", err))
	}
	if cfg.HTTPHeaders != nil {
		for name := range cfg.HTTPHeaders.Headers {
			if _, ok := ReservedHeaders[http.CanonicalHeaderKey(name)]; ok {
				errs = append(errs, &FieldPathError{
					Path: joinPath("http_headers", name),
					Err:  fmt.Errorf("setting header %q is not allowed", http.CanonicalHeaderKey(name)),
				})
			}
		}
	}
	if err := cfg.Validate(); err != nil {
		// HTTPClientConfig.Validate re-checks the nested sections validated
		// above; skip the duplicates so every offending location is reported
		// exactly once. The nested validators fail fast on the first error, so
		// an identity comparison is enough to recognize their messages.
		if !alreadyReported(err, errs) {
			errs = append(errs, atPath(rootConfigPath, err))
		}
	}

	return errors.Join(errs...)
}

// rootConfigPath labels validation errors applying to the configuration
// document as a whole rather than a specific nested item.
const rootConfigPath = "<root>"

// alreadyReported reports whether err repeats an error already attached at a
// more specific nested path.
func alreadyReported(err error, errs []error) bool {
	for _, existing := range errs {
		var fieldErr *FieldPathError
		if errors.As(existing, &fieldErr) && fieldErr.Err.Error() == err.Error() {
			return true
		}
	}
	return false
}

// deepCopyHTTPClientConfig returns an independent copy of cfg by round-tripping
// it through YAML. Secret values are temporarily un-redacted for the copy and
// re-redacted afterwards. The redaction switch is a process-global variable,
// so the un-redacted window is guarded by marshalSecretMu to stay safe under
// concurrent reloads.
var marshalSecretMu sync.Mutex

func deepCopyHTTPClientConfig(cfg *HTTPClientConfig) (*HTTPClientConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	marshalSecretMu.Lock()
	previous := MarshalSecretValue
	MarshalSecretValue = true
	raw, err := yaml.Marshal(cfg)
	MarshalSecretValue = previous
	marshalSecretMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("marshalling configuration for copy: %w", err)
	}
	dup := &HTTPClientConfig{}
	if err := unmarshalHTTPClientConfig(raw, dup); err != nil {
		return nil, fmt.Errorf("copying configuration: %w", err)
	}
	return dup, nil
}

// ConfigStore holds the currently active configuration behind a read/write
// lock and makes hot reloads atomic: a new configuration is parsed and fully
// validated before it replaces the running one. If any item fails validation,
// the previously active configuration is kept untouched and the running
// service keeps using it without interruption.
type ConfigStore struct {
	mu      sync.RWMutex
	current *HTTPClientConfig
}

// NewConfigStore creates a store seeded with an initial configuration. The
// initial configuration is assumed to have already been validated by the
// caller (for example through LoadHTTPConfigFile).
func NewConfigStore(initial *HTTPClientConfig) *ConfigStore {
	return &ConfigStore{current: initial}
}

// Current returns the currently active configuration. The returned pointer
// must be treated as read-only: callers must not mutate it, as in-flight
// requests may be reading it concurrently.
func (s *ConfigStore) Current() *HTTPClientConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// parseAndValidate parses content into a fresh configuration instance, runs
// every validation check against a copy and only returns the configuration
// when all items are valid. The running configuration is never touched by
// this method.
func (s *ConfigStore) parseAndValidate(content, dir string) (*HTTPClientConfig, error) {
	candidate := &HTTPClientConfig{}

	if err := unmarshalHTTPClientConfig([]byte(content), candidate); err != nil {
		return nil, annotateYAMLErrors(err)
	}
	candidate.SetDirectory(dir)

	// Validate against a throwaway copy: HTTPClientConfig.Validate mutates
	// its receiver while normalizing deprecated fields, and a rejected
	// candidate must never carry half-applied normalization.
	validationCopy, err := deepCopyHTTPClientConfig(candidate)
	if err != nil {
		return nil, err
	}
	if err := validateHTTPClientConfig(validationCopy); err != nil {
		return nil, err
	}
	return candidate, nil
}

// rawHTTPClientConfig is the same shape as HTTPClientConfig but without its
// UnmarshalYAML method, so YAML decoding performs a purely structural parse
// without running semantic validation half-way through decoding. All semantic
// checks are then driven by validateHTTPClientConfig against a separate copy,
// which is what makes reloads all-or-nothing.
type rawHTTPClientConfig HTTPClientConfig

// unmarshalHTTPClientConfig strictly decodes content into cfg without
// triggering the validation embedded in HTTPClientConfig.UnmarshalYAML.
func unmarshalHTTPClientConfig(content []byte, cfg *HTTPClientConfig) error {
	raw := (*rawHTTPClientConfig)(cfg)
	*raw = rawHTTPClientConfig(DefaultHTTPClientConfig)
	return yaml.UnmarshalStrict(content, raw)
}

// Reload parses and fully validates content and only then swaps it in as the
// active configuration. When validation fails for one or more items, the
// previously active configuration remains in place and a joined
// FieldPathError list describing every offending location is returned.
//
// Reload only takes the write lock for the final pointer swap, so readers
// serving traffic are never blocked by parsing or validation work.
func (s *ConfigStore) Reload(content []byte) error {
	candidate, err := s.parseAndValidate(string(content), "")
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.current = candidate
	s.mu.Unlock()
	return nil
}

// ReloadFile reads the configuration file at filename, validates its full
// content and atomically swaps it in when every item is valid. Relative file
// references inside the configuration are resolved against the directory of
// filename, matching LoadHTTPConfigFile semantics.
func (s *ConfigStore) ReloadFile(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	candidate, err := s.parseAndValidate(string(content), filepath.Dir(filename))
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.current = candidate
	s.mu.Unlock()
	return nil
}

// annotateYAMLErrors makes sure structural YAML errors keep their line
// information and are wrapped as FieldPathError values rooted at the
// configuration document.
func annotateYAMLErrors(err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		wrapped := make([]error, 0, len(typeErr.Errors))
		for _, issue := range typeErr.Errors {
			line, msg := splitYAMLLine(issue)
			wrapped = append(wrapped, &FieldPathError{
				Path: "",
				Line: line,
				Err:  errors.New(msg),
			})
		}
		return errors.Join(wrapped...)
	}
	line, msg := splitYAMLLine(err.Error())
	return &FieldPathError{Path: "", Line: line, Err: errors.New(msg)}
}

// splitYAMLLine splits an error message of the form "line N: message" as
// produced by go.yaml.in/yaml/v2 into the line number and the remaining
// message. A zero line is returned when the message carries no line prefix.
func splitYAMLLine(message string) (int, string) {
	const prefix = "line "
	if !strings.HasPrefix(message, prefix) {
		return 0, message
	}
	rest := message[len(prefix):]
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return 0, message
	}
	line := 0
	for _, r := range rest[:colon] {
		if r < '0' || r > '9' {
			return 0, message
		}
		line = line*10 + int(r-'0')
	}
	return line, strings.TrimSpace(rest[colon+1:])
}
