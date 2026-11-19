// Copyright 2014 The Prometheus Authors
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

package model

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLabelsToSignature(t *testing.T) {
	scenarios := []struct {
		in  map[string]string
		out uint64
	}{
		{
			in:  map[string]string{},
			out: 14695981039346656037,
		},
		{
			in:  map[string]string{"name": "garland, briggs", "fear": "love is not enough"},
			out: 5799056148416392346,
		},
	}

	for i, scenario := range scenarios {
		actual := LabelsToSignature(scenario.in)

		if actual != scenario.out {
			t.Errorf("%d. expected %d, got %d", i, scenario.out, actual)
		}
	}
}

func TestMetricToFingerprint(t *testing.T) {
	scenarios := []struct {
		in  LabelSet
		out Fingerprint
	}{
		{
			in:  LabelSet{},
			out: 14695981039346656037,
		},
		{
			in:  LabelSet{"name": "garland, briggs", "fear": "love is not enough"},
			out: 5799056148416392346,
		},
	}

	for i, scenario := range scenarios {
		actual := labelSetToFingerprint(scenario.in)

		if actual != scenario.out {
			t.Errorf("%d. expected %d, got %d", i, scenario.out, actual)
		}
	}
}

func TestStableFingerprintOrderIndependent(t *testing.T) {
	labels := []LabelSet{
		{
			"__name__": "http_requests_total",
			"job":      "api",
			"instance": "10.0.0.1:8080",
		},
		{
			"instance": "10.0.0.1:8080",
			"job":      "api",
			"__name__": "http_requests_total",
		},
		{
			"job":      "api",
			"__name__": "http_requests_total",
			"instance": "10.0.0.1:8080",
		},
	}

	expected := labels[0].StableFingerprint()
	if expected != 13595103726509818864 {
		t.Errorf("unexpected stable fingerprint snapshot: %d", expected)
	}
	for i, labelSet := range labels[1:] {
		if actual := labelSet.StableFingerprint(); actual != expected {
			t.Errorf("scenario %d: expected stable fingerprint %d, got %d", i+1, expected, actual)
		}
	}

	stringLabels := map[string]string{
		"instance": "10.0.0.1:8080",
		"__name__": "http_requests_total",
		"job":      "api",
	}
	if actual := LabelsToStableSignature(stringLabels); actual != uint64(expected) {
		t.Errorf("expected string label signature %d, got %d", expected, actual)
	}
}

func TestStableFingerprintDistinguishesSets(t *testing.T) {
	first := LabelSet{
		"a": "bb",
		"b": "c",
	}
	second := LabelSet{
		"a":  "b",
		"bb": "c",
	}

	if first.StableFingerprint() == second.StableFingerprint() {
		t.Fatal("expected different label sets to have different stable fingerprints")
	}
}

func TestFingerprintAllocations(t *testing.T) {
	labels := LabelSet{
		"__name__": "http_requests_total",
		"job":      "api",
		"instance": "10.0.0.1:8080",
		"method":   "GET",
		"status":   "200",
		"cluster":  "prod",
	}
	stringLabels := map[string]string{
		"__name__": "http_requests_total",
		"job":      "api",
		"instance": "10.0.0.1:8080",
		"method":   "GET",
		"status":   "200",
		"cluster":  "prod",
	}
	excluded := map[LabelName]struct{}{"cluster": {}}

	for name, fn := range map[string]func(){
		"Fingerprint": func() {
			_ = labels.Fingerprint()
		},
		"StableFingerprint": func() {
			_ = labels.StableFingerprint()
		},
		"FastFingerprint": func() {
			_ = labels.FastFingerprint()
		},
		"LabelsToSignature": func() {
			_ = LabelsToSignature(stringLabels)
		},
		"LabelsToStableSignature": func() {
			_ = LabelsToStableSignature(stringLabels)
		},
		"SignatureWithoutLabels": func() {
			_ = SignatureWithoutLabels(Metric(labels), excluded)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if allocs := testing.AllocsPerRun(1000, fn); allocs != 0 {
				t.Errorf("expected no allocations, got %f", allocs)
			}
		})
	}
}

func TestMetricToFastFingerprint(t *testing.T) {
	scenarios := []struct {
		in  LabelSet
		out Fingerprint
	}{
		{
			in:  LabelSet{},
			out: 14695981039346656037,
		},
		{
			in:  LabelSet{"name": "garland, briggs", "fear": "love is not enough"},
			out: 12952432476264840823,
		},
	}

	for i, scenario := range scenarios {
		actual := labelSetToFastFingerprint(scenario.in)

		if actual != scenario.out {
			t.Errorf("%d. expected %d, got %d", i, scenario.out, actual)
		}
	}
}

func TestSignatureForLabels(t *testing.T) {
	scenarios := []struct {
		in     Metric
		labels LabelNames
		out    uint64
	}{
		{
			in:     Metric{},
			labels: nil,
			out:    14695981039346656037,
		},
		{
			in:     Metric{},
			labels: LabelNames{"empty"},
			out:    7187873163539638612,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: LabelNames{"empty"},
			out:    7187873163539638612,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: LabelNames{"fear", "name"},
			out:    5799056148416392346,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough", "foo": "bar"},
			labels: LabelNames{"fear", "name"},
			out:    5799056148416392346,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: LabelNames{},
			out:    14695981039346656037,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: nil,
			out:    14695981039346656037,
		},
	}

	for i, scenario := range scenarios {
		actual := SignatureForLabels(scenario.in, scenario.labels...)

		if actual != scenario.out {
			t.Errorf("%d. expected %d, got %d", i, scenario.out, actual)
		}
	}
}

func TestSignatureWithoutLabels(t *testing.T) {
	scenarios := []struct {
		in     Metric
		labels map[LabelName]struct{}
		out    uint64
	}{
		{
			in:     Metric{},
			labels: nil,
			out:    14695981039346656037,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: map[LabelName]struct{}{"fear": {}, "name": {}},
			out:    14695981039346656037,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough", "foo": "bar"},
			labels: map[LabelName]struct{}{"foo": {}},
			out:    5799056148416392346,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: map[LabelName]struct{}{},
			out:    5799056148416392346,
		},
		{
			in:     Metric{"name": "garland, briggs", "fear": "love is not enough"},
			labels: nil,
			out:    5799056148416392346,
		},
	}

	for i, scenario := range scenarios {
		actual := SignatureWithoutLabels(scenario.in, scenario.labels)

		if actual != scenario.out {
			t.Errorf("%d. expected %d, got %d", i, scenario.out, actual)
		}
	}
}

func benchmarkLabelToSignature(b *testing.B, l map[string]string, e uint64) {
	for i := 0; i < b.N; i++ {
		a := LabelsToSignature(l)
		require.Equalf(b, a, e, "expected signature of %d for %s, got %d", e, l, a)
	}
}

func BenchmarkLabelToSignatureScalar(b *testing.B) {
	benchmarkLabelToSignature(b, nil, 14695981039346656037)
}

func BenchmarkLabelToSignatureSingle(b *testing.B) {
	benchmarkLabelToSignature(b, map[string]string{"first-label": "first-label-value"}, 5146282821936882169)
}

func BenchmarkLabelToSignatureDouble(b *testing.B) {
	benchmarkLabelToSignature(b, map[string]string{"first-label": "first-label-value", "second-label": "second-label-value"}, 3195800080984914717)
}

func BenchmarkLabelToSignatureTriple(b *testing.B) {
	benchmarkLabelToSignature(b, map[string]string{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 13843036195897128121)
}

func benchmarkMetricToFingerprint(b *testing.B, ls LabelSet, e Fingerprint) {
	for i := 0; i < b.N; i++ {
		a := labelSetToFingerprint(ls)
		require.Equalf(b, a, e, "expected signature of %d for %s, got %d", e, ls, a)
	}
}

func BenchmarkMetricToFingerprintScalar(b *testing.B) {
	benchmarkMetricToFingerprint(b, nil, 14695981039346656037)
}

func BenchmarkMetricToFingerprintSingle(b *testing.B) {
	benchmarkMetricToFingerprint(b, LabelSet{"first-label": "first-label-value"}, 5146282821936882169)
}

func BenchmarkMetricToFingerprintDouble(b *testing.B) {
	benchmarkMetricToFingerprint(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value"}, 3195800080984914717)
}

func BenchmarkMetricToFingerprintTriple(b *testing.B) {
	benchmarkMetricToFingerprint(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 13843036195897128121)
}

func benchmarkMetricToStableFingerprint(b *testing.B, ls LabelSet) {
	for b.Loop() {
		_ = labelSetToStableFingerprint(ls)
	}
}

func BenchmarkMetricToStableFingerprintScalar(b *testing.B) {
	benchmarkMetricToStableFingerprint(b, nil)
}

func BenchmarkMetricToStableFingerprintSingle(b *testing.B) {
	benchmarkMetricToStableFingerprint(b, LabelSet{"first-label": "first-label-value"})
}

func BenchmarkMetricToStableFingerprintDouble(b *testing.B) {
	benchmarkMetricToStableFingerprint(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value"})
}

func BenchmarkMetricToStableFingerprintTriple(b *testing.B) {
	benchmarkMetricToStableFingerprint(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"})
}

func benchmarkMetricToFastFingerprint(b *testing.B, ls LabelSet, e Fingerprint) {
	for i := 0; i < b.N; i++ {
		a := labelSetToFastFingerprint(ls)
		require.Equalf(b, a, e, "expected signature of %d for %s, got %d", e, ls, a)
	}
}

func BenchmarkMetricToFastFingerprintScalar(b *testing.B) {
	benchmarkMetricToFastFingerprint(b, nil, 14695981039346656037)
}

func BenchmarkMetricToFastFingerprintSingle(b *testing.B) {
	benchmarkMetricToFastFingerprint(b, LabelSet{"first-label": "first-label-value"}, 5147259542624943964)
}

func BenchmarkMetricToFastFingerprintDouble(b *testing.B) {
	benchmarkMetricToFastFingerprint(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value"}, 18269973311206963528)
}

func BenchmarkMetricToFastFingerprintTriple(b *testing.B) {
	benchmarkMetricToFastFingerprint(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 15738406913934009676)
}

func BenchmarkEmptyLabelSignature(b *testing.B) {
	input := []map[string]string{nil, {}}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	alloc := ms.Alloc

	for _, labels := range input {
		LabelsToSignature(labels)
	}

	runtime.ReadMemStats(&ms)

	got := ms.Alloc
	require.Equalf(b, alloc, got, "expected LabelsToSignature with empty labels not to perform allocations")
}

func benchmarkMetricToFastFingerprintConc(b *testing.B, ls LabelSet, e Fingerprint, concLevel int) {
	var start, end sync.WaitGroup
	start.Add(1)
	end.Add(concLevel)
	errc := make(chan error, 1)

	for range concLevel {
		go func() {
			start.Wait()
			for j := b.N / concLevel; j >= 0; j-- {
				if a := labelSetToFastFingerprint(ls); a != e {
					select {
					case errc <- fmt.Errorf("expected signature of %d for %s, got %d", e, ls, a):
					default:
					}
				}
			}
			end.Done()
		}()
	}
	b.ResetTimer()
	start.Done()
	end.Wait()

	select {
	case err := <-errc:
		b.Fatal(err)
	default:
	}
}

func BenchmarkMetricToFastFingerprintTripleConc1(b *testing.B) {
	benchmarkMetricToFastFingerprintConc(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 15738406913934009676, 1)
}

func BenchmarkMetricToFastFingerprintTripleConc2(b *testing.B) {
	benchmarkMetricToFastFingerprintConc(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 15738406913934009676, 2)
}

func BenchmarkMetricToFastFingerprintTripleConc4(b *testing.B) {
	benchmarkMetricToFastFingerprintConc(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 15738406913934009676, 4)
}

func BenchmarkMetricToFastFingerprintTripleConc8(b *testing.B) {
	benchmarkMetricToFastFingerprintConc(b, LabelSet{"first-label": "first-label-value", "second-label": "second-label-value", "third-label": "third-label-value"}, 15738406913934009676, 8)
}
