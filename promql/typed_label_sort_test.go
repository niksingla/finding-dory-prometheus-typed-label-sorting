// Copyright The Prometheus Authors
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

package promql

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
)

func TestCompareLabelValuesTypedOrder(t *testing.T) {
	ordered := []string{
		// Leading whitespace: never typed, first, natural among themselves.
		" 2", " 10",
		// Positive infinity, finite numbers, negative infinity.
		"+Inf",
		"-2", "0", "2", "+3", "10", "1e2", "99999999999999999999999999999999999999",
		"-Inf",
		// Durations.
		"-30m", "90s", "1e2s", "2m", "1h", "1h30m",
		// Bytes.
		"500B", "1KB", "1KiB", "1024B", "2MiB",
		// Semantic versions.
		"v1.2.3", "1.10.0", "2.0.0-alpha", "2.0.0",
		// IP addresses: IPv4 before IPv6.
		"10.0.0.2", "10.0.0.10", "192.168.0.1", "::1", "::ffff:192.168.0.1", "2001:db8::1",
		// CIDR prefixes: IPv4 before IPv6, smaller prefix first on equal network.
		"10.0.0.0/8", "10.0.0.0/24", "10.0.1.0/24", "2001:db8::/32",
		// Timestamps.
		"2024-01-02T00:00:00Z", "2024-01-02T01:00:00+00:00", "2025-06-01T00:00:00Z",
		// Untyped, natural sort.
		"", "1e", "NaN", "abc2", "abc10", "v1.2",
	}
	for i, a := range ordered {
		require.Equal(t, 0, compareLabelValues(a, a), "value %q compared to itself", a)
		for j, b := range ordered {
			if i == j {
				continue
			}
			got := compareLabelValues(a, b)
			if i < j {
				require.True(t, got < 0, "expected %q < %q, got %d", a, b, got)
			} else {
				require.True(t, got > 0, "expected %q > %q, got %d", a, b, got)
			}
		}
	}
}

func TestCompareLabelValuesTypedTiesAndPrecision(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Equal typed values tie-break on natural order of the originals.
		{"1", "1.0", -1},
		{"+1", "1", -1},
		{"1h", "60m", -1},
		{"1024B", "1KiB", 1}, // Natural: digit run 1 sorts before 1024.
		{"1.2.3", "v1.2.3", -1},
		{"2024-01-02T02:00:00+02:00", "2024-01-02T00:00:00Z", 1},
		// Exact magnitude comparison beyond float64 precision.
		{"9007199254740992", "9007199254740993", -1},
		{"123456789012345678901234567890", "123456789012345678901234567891", -1},
		{"99999999999999999999999999h", "100000000000000000000000000h", -1},
		{"1e100", "2e99", 1},
		// Bare exponent and NaN are untyped, after all typed values.
		{"1e", "-Inf", 1},
		{"NaN", "2024-01-02T00:00:00Z", 1},
		{"1e+", "1e", 1},
		// Invalid semver/IP fall back to untyped.
		{"1.2.3.4.5", "10.0.0.1", 1},
		{"01.2.3", "1.2.3", 1},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, sign(compareLabelValues(tc.a, tc.b)), "%q vs %q", tc.a, tc.b)
		require.Equal(t, -tc.want, sign(compareLabelValues(tc.b, tc.a)), "%q vs %q", tc.b, tc.a)
	}
}

func TestSortByLabelsAscDescShareTypedOrder(t *testing.T) {
	mk := func(vals ...string) Vector {
		vec := make(Vector, 0, len(vals))
		for _, v := range vals {
			vec = append(vec, Sample{Metric: labels.FromStrings("val", v)})
		}
		return vec
	}
	values := func(vec Vector) []string {
		out := make([]string, 0, len(vec))
		for _, s := range vec {
			out = append(out, s.Metric.Get("val"))
		}
		return out
	}
	input := []string{"1h", "10", " 5", "abc", "2", "+Inf"}
	require.Equal(t,
		[]string{" 5", "+Inf", "2", "10", "1h", "abc"},
		values(sortByLabels(mk(input...), []string{"val"}, false)))
	require.Equal(t,
		[]string{"abc", "1h", "10", "2", "+Inf", " 5"},
		values(sortByLabels(mk(input...), []string{"val"}, true)))
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	default:
		return 0
	}
}
