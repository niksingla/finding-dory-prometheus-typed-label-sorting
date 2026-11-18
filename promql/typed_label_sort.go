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
	"bytes"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/facette/natsort"

	"github.com/prometheus/prometheus/model/labels"
)

// labelValueKind is the typed class of a label value, in sort order.
type labelValueKind int

const (
	labelKindLeadingWhitespace labelValueKind = iota
	labelKindPositiveInfinity
	labelKindFiniteNumeric
	labelKindNegativeInfinity
	labelKindDuration
	labelKindBytes
	labelKindSemver
	labelKindIP
	labelKindCIDR
	labelKindTimestamp
	labelKindUntyped
)

type parsedLabelValue struct {
	kind    labelValueKind
	mag     *big.Rat // Finite numeric, duration (ns), and bytes magnitudes.
	semver  []string // Core components, plus prerelease identifiers below.
	pre     []string
	hasPre  bool
	ip      netip.Addr
	prefix  netip.Prefix
	instant time.Time
}

// compareLabelValues is the shared comparison for sort_by_label (ascending)
// and sort_by_label_desc (descending, which negates it). Values are first
// ordered by typed class, then by typed value within the class, then by
// natural sort of the original strings.
func compareLabelValues(a, b string) int {
	if a == b {
		return 0
	}
	pa, pb := parseLabelValue(a), parseLabelValue(b)
	if pa.kind != pb.kind {
		return cmpInt(int(pa.kind), int(pb.kind))
	}
	if c := pa.compareSameKind(pb); c != 0 {
		return c
	}
	return naturalCompareLabel(a, b)
}

func (p parsedLabelValue) compareSameKind(o parsedLabelValue) int {
	switch p.kind {
	case labelKindLeadingWhitespace, labelKindUntyped,
		labelKindPositiveInfinity, labelKindNegativeInfinity:
		return 0 // Decided by natural sort of the originals.
	case labelKindFiniteNumeric, labelKindDuration, labelKindBytes:
		return p.mag.Cmp(o.mag)
	case labelKindSemver:
		return compareSemver(p, o)
	case labelKindIP:
		if c := cmpInt(ipFamilyRank(p.ip), ipFamilyRank(o.ip)); c != 0 {
			return c
		}
		pa, pb := p.ip.As16(), o.ip.As16()
		return bytes.Compare(pa[:], pb[:])
	case labelKindCIDR:
		if c := cmpInt(ipFamilyRank(p.prefix.Addr()), ipFamilyRank(o.prefix.Addr())); c != 0 {
			return c
		}
		pa := p.prefix.Masked().Addr().As16()
		pb := o.prefix.Masked().Addr().As16()
		if c := bytes.Compare(pa[:], pb[:]); c != 0 {
			return c
		}
		return cmpInt(p.prefix.Bits(), o.prefix.Bits())
	case labelKindTimestamp:
		switch {
		case p.instant.Before(o.instant):
			return -1
		case p.instant.After(o.instant):
			return 1
		default:
			return 0
		}
	}
	return 0
}

// parseLabelValue classifies s. Leading-whitespace and empty values are
// never typed; parsing otherwise follows the class order.
func parseLabelValue(s string) parsedLabelValue {
	if s != "" {
		if r, _ := utf8.DecodeRuneInString(s); unicode.IsSpace(r) {
			return parsedLabelValue{kind: labelKindLeadingWhitespace}
		}
	}
	switch strings.ToLower(s) {
	case "inf", "+inf", "infinity", "+infinity":
		return parsedLabelValue{kind: labelKindPositiveInfinity}
	case "-inf", "-infinity":
		return parsedLabelValue{kind: labelKindNegativeInfinity}
	}
	if s == "" {
		return parsedLabelValue{kind: labelKindUntyped}
	}
	if v, ok := parseDecimalRat(s); ok {
		return parsedLabelValue{kind: labelKindFiniteNumeric, mag: v}
	}
	if v, ok := parseDurationRat(s); ok {
		return parsedLabelValue{kind: labelKindDuration, mag: v}
	}
	if v, ok := parseBytesRat(s); ok {
		return parsedLabelValue{kind: labelKindBytes, mag: v}
	}
	if v, ok := parseSemver(s); ok {
		return v
	}
	if ip, err := netip.ParseAddr(s); err == nil && !strings.Contains(s, "/") && ip.Zone() == "" {
		return parsedLabelValue{kind: labelKindIP, ip: ip}
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return parsedLabelValue{kind: labelKindCIDR, prefix: p}
	}
	if ts, ok := parseTimestamp(s); ok {
		return parsedLabelValue{kind: labelKindTimestamp, instant: ts}
	}
	return parsedLabelValue{kind: labelKindUntyped}
}

// ipFamilyRank places IPv4 before IPv6; IPv4-mapped IPv6 counts as IPv6.
func ipFamilyRank(a netip.Addr) int {
	if a.Is4() {
		return 0
	}
	return 1
}

func naturalCompareLabel(a, b string) int {
	if a == b {
		return 0
	}
	ab, ba := natsort.Compare(a, b), natsort.Compare(b, a)
	switch {
	case ab && !ba:
		return -1
	case ba && !ab:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// sortByLabels sorts vec by the given labels using compareLabelValues,
// falling back to the full label set. Descending negates both.
func sortByLabels(vec Vector, lbls []string, desc bool) Vector {
	slices.SortFunc(vec, func(a, b Sample) int {
		for _, label := range lbls {
			lv1, lv2 := a.Metric.Get(label), b.Metric.Get(label)
			if lv1 == lv2 {
				continue
			}
			if c := compareLabelValues(lv1, lv2); c != 0 {
				if desc {
					return -c
				}
				return c
			}
		}
		c := labels.Compare(a.Metric, b.Metric)
		if desc {
			return -c
		}
		return c
	})
	return vec
}

// scanDecimal scans a signed decimal with optional exponent at s[i:]. A
// bare exponent marker (no digits after e/E and its optional sign) fails.
func scanDecimal(s string, i int) (*big.Rat, int, bool) {
	start := i
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	intStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	intDigits := s[intStart:i]
	fracDigits := ""
	if i < len(s) && s[i] == '.' {
		i++
		fs := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		fracDigits = s[fs:i]
	}
	if intDigits == "" && fracDigits == "" {
		return nil, start, false
	}
	exp := 0
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		es := j
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if es == j {
			return nil, start, false
		}
		e, ok := atoiBounded(s[i+1 : j])
		if !ok {
			return nil, start, false
		}
		exp = e
		i = j
	}
	neg := start < len(s) && s[start] == '-'
	return decimalRat(neg, intDigits+fracDigits, exp-len(fracDigits)), i, true
}

func parseDecimalRat(s string) (*big.Rat, bool) {
	v, next, ok := scanDecimal(s, 0)
	return v, ok && next == len(s)
}

// decimalRat builds digits * 10^scale exactly, however large.
func decimalRat(neg bool, digits string, scale int) *big.Rat {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return new(big.Rat)
	}
	mant, _ := new(big.Int).SetString(digits, 10)
	out := new(big.Rat)
	if scale >= 0 {
		mul := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
		out.SetInt(mant.Mul(mant, mul))
	} else {
		den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-scale)), nil)
		out.SetFrac(mant, den)
	}
	if neg {
		out.Neg(out)
	}
	return out
}

// atoiBounded parses a signed decimal exponent, rejecting absurd sizes.
func atoiBounded(s string) (int, bool) {
	neg := false
	if strings.HasPrefix(s, "+") {
		s = s[1:]
	} else if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return 0, true
	}
	if len(s) > 6 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

var durationUnits = []struct {
	suffix string
	ns     int64
}{
	{"ns", 1},
	{"us", 1_000},
	{"µs", 1_000},
	{"μs", 1_000},
	{"ms", 1_000_000},
	{"s", 1_000_000_000},
	{"m", 60 * 1_000_000_000},
	{"h", 3600 * 1_000_000_000},
	{"d", 24 * 3600 * 1_000_000_000},
	{"w", 7 * 24 * 3600 * 1_000_000_000},
	{"y", 365 * 24 * 3600 * 1_000_000_000},
}

// parseDurationRat parses one or more <decimal><unit> terms (Prometheus
// units), each coefficient optionally signed and in scientific notation.
func parseDurationRat(s string) (*big.Rat, bool) {
	total, i, terms := new(big.Rat), 0, 0
	for i < len(s) {
		coeff, next, ok := scanDecimal(s, i)
		if !ok {
			return nil, false
		}
		matched := false
		for _, u := range durationUnits {
			if strings.HasPrefix(s[next:], u.suffix) {
				// Prefer the longest unit (ms over m) handled by order
				// below via two-letter check.
				term := new(big.Rat).Mul(coeff, big.NewRat(u.ns, 1))
				total.Add(total, term)
				i, matched, terms = next+len(u.suffix), true, terms+1
				break
			}
		}
		if !matched {
			return nil, false
		}
	}
	return total, terms > 0
}

var byteUnits = map[string]*big.Rat{}

func byteUnitRat(factor *big.Int) *big.Rat { return new(big.Rat).SetInt(factor) }

func powRat(base, exp int64) *big.Rat {
	return byteUnitRat(new(big.Int).Exp(big.NewInt(base), big.NewInt(exp), nil))
}

func init() {
	decimalNames := []string{"KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	binaryNames := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"}
	byteUnits["B"] = big.NewRat(1, 1)
	for i, name := range decimalNames {
		f := powRat(1000, int64(i+1))
		byteUnits[name] = f
		byteUnits[strings.ToLower(name)] = f
		single := name[:1]
		if _, ok := byteUnits[single]; !ok {
			byteUnits[single] = powRat(1024, int64(i+1))
		}
	}
	for i, name := range binaryNames {
		f := powRat(1024, int64(i+1))
		byteUnits[name] = f
		byteUnits[strings.ToLower(name)] = f
	}
	byteUnits["kB"] = powRat(1000, 1)
	byteUnits["byte"] = big.NewRat(1, 1)
	byteUnits["bytes"] = big.NewRat(1, 1)
}

// parseBytesRat parses a signed/scientific decimal plus a byte unit.
func parseBytesRat(s string) (*big.Rat, bool) {
	coeff, next, ok := scanDecimal(s, 0)
	if !ok || next >= len(s) {
		return nil, false
	}
	unit := strings.TrimPrefix(s[next:], " ")
	f, ok := byteUnits[unit]
	if !ok {
		return nil, false
	}
	return new(big.Rat).Mul(coeff, f), true
}

// parseSemver parses strict semver with an optional leading v.
func parseSemver(s string) (parsedLabelValue, bool) {
	out := parsedLabelValue{kind: labelKindSemver}
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !validSemverIDList(s[i+1:], false) {
			return out, false
		}
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if !validSemverIDList(s[i+1:], true) {
			return out, false
		}
		out.pre, out.hasPre = strings.Split(s[i+1:], "."), true
		s = s[:i]
	}
	core := strings.Split(s, ".")
	if len(core) != 3 {
		return out, false
	}
	for _, c := range core {
		if !validSemverNumber(c) {
			return out, false
		}
	}
	out.semver = core
	return out, true
}

func validSemverNumber(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validSemverIDList(s string, prerelease bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
			if c < '0' || c > '9' {
				numeric = false
			}
		}
		if prerelease && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func compareSemver(a, b parsedLabelValue) int {
	for i := range a.semver {
		if c := compareNumericString(a.semver[i], b.semver[i]); c != 0 {
			return c
		}
	}
	if a.hasPre != b.hasPre {
		if a.hasPre {
			return -1 // A prerelease sorts before its release.
		}
		return 1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := isAllDigits(x), isAllDigits(y)
		switch {
		case xn && yn:
			if c := compareNumericString(x, y); c != 0 {
				return c
			}
		case xn:
			return -1 // Numeric identifiers sort before alphanumeric.
		case yn:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a.pre), len(b.pre))
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// compareNumericString compares digit strings of any length exactly.
func compareNumericString(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmpInt(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

var timestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	time.RFC1123Z,
	time.RFC1123,
}

func parseTimestamp(s string) (time.Time, bool) {
	for _, layout := range timestampLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
