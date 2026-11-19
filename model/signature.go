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
	"slices"
)

const (
	// labelNamesStackSize is large enough for the vast majority of label sets.
	// Keeping the scratch space on the stack avoids an allocation on the
	// fingerprinting hot path. Larger sets fall back to the heap.
	labelNamesStackSize = 64

	stableFingerprintSeed = 0x9e3779b97f4a7c15
)

// SeparatorByte is a byte that cannot occur in valid UTF-8 sequences and is
// used to separate label names, label values, and other strings from each other
// when calculating their combined hash value (aka signature aka fingerprint).
const SeparatorByte byte = 255

// cache the signature of an empty label set.
var emptyLabelSignature = hashNew()

// LabelsToSignature returns a quasi-unique signature (i.e., fingerprint) for a
// given label set. (Collisions are possible but unlikely if the number of label
// sets the function is applied to is small.)
func LabelsToSignature(labels map[string]string) uint64 {
	if len(labels) == 0 {
		return emptyLabelSignature
	}

	var labelNamesBuffer [labelNamesStackSize]string
	labelNames := labelNamesBuffer[:0]
	if len(labels) > labelNamesStackSize {
		labelNames = make([]string, 0, len(labels))
	}
	for labelName := range labels {
		labelNames = append(labelNames, labelName)
	}
	slices.Sort(labelNames)

	sum := hashNew()
	for _, labelName := range labelNames {
		sum = hashAdd(sum, labelName)
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, labels[labelName])
		sum = hashAddByte(sum, SeparatorByte)
	}
	return sum
}

// LabelsToStableSignature returns an order-independent signature for a label
// set without sorting its label names.
//
// The returned value is stable for a given label set, but it is not
// interchangeable with the value returned by LabelsToSignature. Callers that
// persist signatures must version them or migrate existing data before
// switching algorithms.
func LabelsToStableSignature(labels map[string]string) uint64 {
	return stableFingerprint(labels)
}

// labelSetToFingerprint works exactly as LabelsToSignature but takes a LabelSet as
// parameter (rather than a label map) and returns a Fingerprint.
func labelSetToFingerprint(ls LabelSet) Fingerprint {
	if len(ls) == 0 {
		return Fingerprint(emptyLabelSignature)
	}

	var labelNamesBuffer [labelNamesStackSize]LabelName
	labelNames := labelNamesBuffer[:0]
	if len(ls) > labelNamesStackSize {
		labelNames = make(LabelNames, 0, len(ls))
	}
	for labelName := range ls {
		labelNames = append(labelNames, labelName)
	}
	slices.Sort(labelNames)

	sum := hashNew()
	for _, labelName := range labelNames {
		sum = hashAdd(sum, string(labelName))
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, string(ls[labelName]))
		sum = hashAddByte(sum, SeparatorByte)
	}
	return Fingerprint(sum)
}

// labelSetToStableFingerprint computes a fingerprint without sorting the label
// names. Each label pair is hashed independently and the results are combined
// with a commutative operation, so map iteration order cannot affect the
// result.
func labelSetToStableFingerprint(ls LabelSet) Fingerprint {
	return Fingerprint(stableFingerprint(ls))
}

func stableFingerprint[K ~string, V ~string](labels map[K]V) uint64 {
	if len(labels) == 0 {
		return emptyLabelSignature
	}
	if len(labels) == 1 {
		for labelName, labelValue := range labels {
			return hashLabelPair(string(labelName), string(labelValue))
		}
	}

	// Seed with the cardinality so that sets of different sizes do not share a
	// commutative accumulator just because their pair hashes happen to cancel.
	sum := uint64(len(labels)) * stableFingerprintSeed
	for labelName, labelValue := range labels {
		sum += mix64(hashLabelPair(string(labelName), string(labelValue)))
	}
	return mix64(sum)
}

func hashLabelPair(labelName, labelValue string) uint64 {
	sum := hashNew()
	sum = hashAdd(sum, labelName)
	sum = hashAddByte(sum, SeparatorByte)
	sum = hashAdd(sum, labelValue)
	sum = hashAddByte(sum, SeparatorByte)
	return sum
}

// mix64 is the SplitMix64 finalizer. It removes the simple algebraic
// relationships left by adding independently hashed label pairs.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// labelSetToFastFingerprint works similar to labelSetToFingerprint but uses a
// faster and less allocation-heavy hash function, which is more susceptible to
// create hash collisions. Therefore, collision detection should be applied.
func labelSetToFastFingerprint(ls LabelSet) Fingerprint {
	if len(ls) == 0 {
		return Fingerprint(emptyLabelSignature)
	}

	var result uint64
	for labelName, labelValue := range ls {
		sum := hashNew()
		sum = hashAdd(sum, string(labelName))
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, string(labelValue))
		result ^= sum
	}
	return Fingerprint(result)
}

// SignatureForLabels works like LabelsToSignature but takes a Metric as
// parameter (rather than a label map) and only includes the labels with the
// specified LabelNames into the signature calculation. The labels passed in
// will be sorted by this function.
func SignatureForLabels(m Metric, labels ...LabelName) uint64 {
	if len(labels) == 0 {
		return emptyLabelSignature
	}

	slices.Sort(labels)

	sum := hashNew()
	for _, label := range labels {
		sum = hashAdd(sum, string(label))
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, string(m[label]))
		sum = hashAddByte(sum, SeparatorByte)
	}
	return sum
}

// SignatureWithoutLabels works like LabelsToSignature but takes a Metric as
// parameter (rather than a label map) and excludes the labels with any of the
// specified LabelNames from the signature calculation.
func SignatureWithoutLabels(m Metric, labels map[LabelName]struct{}) uint64 {
	if len(m) == 0 {
		return emptyLabelSignature
	}

	var labelNamesBuffer [labelNamesStackSize]LabelName
	labelNames := labelNamesBuffer[:0]
	if len(m) > labelNamesStackSize {
		labelNames = make(LabelNames, 0, len(m))
	}
	for labelName := range m {
		if _, exclude := labels[labelName]; !exclude {
			labelNames = append(labelNames, labelName)
		}
	}
	if len(labelNames) == 0 {
		return emptyLabelSignature
	}
	slices.Sort(labelNames)

	sum := hashNew()
	for _, labelName := range labelNames {
		sum = hashAdd(sum, string(labelName))
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, string(m[labelName]))
		sum = hashAddByte(sum, SeparatorByte)
	}
	return sum
}
