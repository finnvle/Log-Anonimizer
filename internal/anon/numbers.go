package anon

import (
	"regexp"
	"strconv"
	"strings"

	"log_anonimizer/internal/vault"
)

// --- payment cards, Thai national IDs, phone numbers -------------------------
//
// Logs are full of long numbers (timestamps, counters, IDs), so each number
// must prove what it is: a card passes the Luhn check and starts with a
// card brand's prefix, a national ID passes its check digit and is written
// 1-2345-67890-12-1 or labelled, a phone number has a Thai or +country shape.

// hasDigits reports whether t has at least n digits.
func hasDigits(t string, n int) bool {
	for i := 0; i < len(t); i++ {
		if isDigit(t[i]) {
			if n--; n == 0 {
				return true
			}
		}
	}
	return false
}

func digitCount(t string) int {
	n := 0
	for i := 0; i < len(t); i++ {
		if isDigit(t[i]) {
			n++
		}
	}
	return n
}

// leftEdge and rightEdge: the number is not glued to a word or a longer
// number, as in "x4111…", "4111…7a", "1.4111…" or "…1111.5".
func leftEdge(t string, s int) bool {
	if s == 0 {
		return true
	}
	c := t[s-1]
	return !(isAlnum(c) || c == '_' || c == '.' && s >= 2 && isDigit(t[s-2]))
}

func rightEdge(t string, e int) bool {
	if e >= len(t) {
		return true
	}
	c := t[e]
	if isAlnum(c) || c == '_' {
		return false
	}
	return !((c == '.' || c == ',' || c == ':') && e+1 < len(t) && isDigit(t[e+1]))
}

func numberEdges(t string, s, e int) bool { return leftEdge(t, s) && rightEdge(t, e) }

// numGroup is one run of digits inside a number written in groups.
type numGroup struct{ s, e int }

func (g numGroup) n() int { return g.e - g.s }

// detectNumbers reads every number written in groups once ("4111 1111 1111
// 1111", "081-234-5678", "1-2345-67890-12-1", "4111111111111111") and
// tries the national ID, card and phone shapes on its groups.
func (sc *Scanner) detectNumbers(t string, out []span) []span {
	a := sc.p.Anonymize
	if !a.CardNumber && !a.NationalID && !a.Phone || !hasDigits(t, 9) {
		return out
	}
	gs := make([]numGroup, 0, 8)
	for i := 0; i < len(t); {
		if !isDigit(t[i]) {
			i++
			continue
		}
		gs = gs[:0]
		j := i
		for {
			k := j
			for k < len(t) && isDigit(t[k]) {
				k++
			}
			gs = append(gs, numGroup{j, k})
			j = k
			if k+1 < len(t) && (t[k] == ' ' || t[k] == '-') && isDigit(t[k+1]) {
				j = k + 1
				continue
			}
			break
		}
		out = sc.numberRun(t, gs, out)
		i = j
	}
	if a.Phone && hasIntlPrefix(t) {
		out = sc.detectIntlPhone(t, out)
	}
	return out
}

// sameSep reports whether the groups are separated by one kind of
// separator: "4111 1111-1111 1111" is not one number.
func sameSep(t string, win []numGroup) bool {
	for k := 2; k < len(win); k++ {
		if t[win[k].s-1] != t[win[1].s-1] {
			return false
		}
	}
	return true
}

func shapeIs(win []numGroup, shape []int) bool {
	if len(win) != len(shape) {
		return false
	}
	for k, g := range win {
		if g.n() != shape[k] {
			return false
		}
	}
	return true
}

func (sc *Scanner) numberRun(t string, gs []numGroup, out []span) []span {
	a := sc.p.Anonymize
	total := 0
	for _, g := range gs {
		total += g.n()
	}
	if total < 9 {
		return out
	}
	last := len(gs) - 1
	// a window may start or end inside the run (after "order 5512 "), but
	// at the run's own ends it must not be glued to anything
	edges := func(i, j int) bool {
		return (i > 0 || leftEdge(t, gs[0].s)) && (j < last || rightEdge(t, gs[last].e))
	}
	add := func(i, j int, k vault.Kind, prio int) {
		out = append(out, span{gs[i].s, gs[j].e, []part{{text: t[gs[i].s:gs[j].e], kind: k}}, prio})
	}
next:
	for i := 0; i < len(gs); i++ {
		if a.NationalID {
			if i+5 <= len(gs) && shapeIs(gs[i:i+5], natIDGroups) && sameSep(t, gs[i:i+5]) && edges(i, i+4) &&
				thaiIDCheck(digitsIn(t[gs[i].s:gs[i+4].e])) {
				add(i, i+4, vault.NatID, prioStructure)
				i += 4
				continue
			}
			if g := gs[i]; g.n() == 13 && edges(i, i) && thaiIDCheck(t[g.s:g.e]) && natIDLabelled(t, g.s) {
				add(i, i, vault.NatID, prioContext) // labelled: wins over a card with the same digits
				continue
			}
		}
		if a.CardNumber {
			for _, shape := range cardShapes {
				j := i + len(shape) - 1
				if j > last || !edges(i, j) {
					continue
				}
				win := gs[i : j+1]
				if len(shape) == 1 {
					if win[0].n() < 13 || win[0].n() > 19 {
						continue
					}
				} else if !shapeIs(win, shape) || !sameSep(t, win) {
					continue
				}
				if isCard(digitsIn(t[gs[i].s:gs[j].e])) {
					add(i, j, vault.Card, prioStructure)
					i = j
					continue next
				}
			}
		}
		if a.Phone {
			if j, ok := thaiPhoneAt(t, gs, i, edges); ok {
				add(i, j, vault.Phone, prioStructure)
				i = j
			}
		}
	}
	return out
}

// --- cards -------------------------------------------------------------------

// cardShapes are the ways card numbers are grouped; {0} is one group of 13
// to 19 digits.
var cardShapes = [][]int{{0}, {4, 4, 4, 4}, {4, 4, 4, 4, 3}, {4, 6, 5}, {4, 6, 4}, {4, 4, 4, 3}, {4, 4, 4, 2}}

func luhn(d string) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// cardBrand reports whether d starts like a Visa, Mastercard, Amex,
// Discover, UnionPay, JCB or Diners number of that length. Numbers starting
// with 1 (epoch times, snowflake IDs) are never cards.
func cardBrand(d string) bool {
	n := len(d)
	if n < 13 || n > 19 {
		return false
	}
	p := func(k int) int { v, _ := strconv.Atoi(d[:k]); return v }
	switch {
	case d[0] == '4':
		return n == 13 || n == 16 || n == 19
	case p(2) >= 51 && p(2) <= 55, p(4) >= 2221 && p(4) <= 2720:
		return n == 16
	case p(2) == 34, p(2) == 37:
		return n == 15
	case p(4) == 6011, p(2) == 65, p(3) >= 644 && p(3) <= 649, p(2) == 62, p(4) >= 3528 && p(4) <= 3589:
		return n >= 16
	case p(3) >= 300 && p(3) <= 305, p(2) == 36, p(2) == 38, p(2) == 39:
		return n >= 14
	}
	return false
}

func isCard(d string) bool { return cardBrand(d) && luhn(d) }

func digitsIn(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// --- Thai national ID --------------------------------------------------------

var natIDGroups = []int{1, 4, 5, 2, 1}

// natIDWords label a plain 13-digit number as a national ID; without one it
// could as well be a time in milliseconds.
var natIDWords = []string{"citizen", "national", "id card", "idcard", "id_card", "id-card", "cid",
	"thai id", "thaiid", "personal id", "personalid", "id no", "idno", "id_no",
	"เลขประจำตัว", "บัตรประชาชน", "เลขบัตร"}

// thaiIDCheck validates the 13th digit of a Thai national ID.
func thaiIDCheck(d string) bool {
	if len(d) != 13 || d[0] == '9' {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(d[i]-'0') * (13 - i)
	}
	return (11-sum%11)%10 == int(d[12]-'0')
}

func natIDLabelled(t string, s int) bool {
	lw := strings.ToLower(t[max(0, s-40):s])
	for _, w := range natIDWords {
		if strings.Contains(lw, w) {
			return true
		}
	}
	return false
}

// --- phone numbers -----------------------------------------------------------

// thaiPhoneGroups: 02-123-4567, 081-234-5678, 081 234 5678, 044-123-456
var thaiPhoneGroups = [][]int{{2, 3, 4}, {3, 3, 4}, {2, 3, 3}, {3, 3, 3}}

// thaiPhoneAt finds a Thai number starting at group i: grouped as above, or
// one group 0812345678. It returns the last group used.
func thaiPhoneAt(t string, gs []numGroup, i int, edges func(i, j int) bool) (int, bool) {
	g := gs[i]
	if t[g.s] != '0' || g.n() < 2 || t[g.s+1] < '2' {
		return 0, false
	}
	// "-" or ":" before belongs to a longer number or a time; "+" before is
	// an encoded space ("q=call+0812345678")
	if g.s > 0 && strings.IndexByte("-:/", t[g.s-1]) >= 0 {
		return 0, false
	}
	end := func(j int) bool {
		// "081-234-5678-9" is a longer number
		return edges(i, j) && !(j+1 < len(gs) && t[gs[j].e] == '-')
	}
	for _, shape := range thaiPhoneGroups {
		j := i + len(shape) - 1
		if j < len(gs) && shapeIs(gs[i:j+1], shape) && sameSep(t, gs[i:j+1]) && end(j) {
			return j, true
		}
	}
	if g.n() == 10 && strings.IndexByte("689", t[g.s+1]) >= 0 && end(i) {
		return i, true
	}
	return 0, false
}

// +66 2 123 4567, +66-81-234-5678, +6681234567, +1 (415) 555-0100
var rePhoneIntl = regexp.MustCompile(`\+[1-9]\d{0,2}(?:[ -]?\(\d{1,4}\)|[ -]?\d{1,4})(?:[ -]?\d{2,4}){1,4}`)

func hasIntlPrefix(t string) bool {
	for i := strings.IndexByte(t, '+'); i >= 0 && i+1 < len(t); {
		if t[i+1] >= '1' && t[i+1] <= '9' {
			return true
		}
		j := strings.IndexByte(t[i+1:], '+')
		if j < 0 {
			return false
		}
		i += j + 1
	}
	return false
}

func (sc *Scanner) detectIntlPhone(t string, out []span) []span {
	for _, m := range rePhoneIntl.FindAllStringIndex(t, -1) {
		s, e := m[0], m[1]
		if n := digitCount(t[s:e]); n < 8 || n > 15 || !numberEdges(t, s, e) {
			continue
		}
		out = append(out, span{s, e, []part{{text: t[s:e], kind: vault.Phone}}, prioStructure})
	}
	return out
}
