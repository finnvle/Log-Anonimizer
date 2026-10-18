package anon

// acMatcher is an Aho-Corasick automaton for finding many literal patterns in
// one pass. Matching is ASCII case-insensitive; non-ASCII bytes (Thai text,
// for example) must match exactly. Byte offsets are those of the input.
type acMatcher struct {
	nodes []acNode
	pats  []string
}

type acNode struct {
	next map[byte]int32
	fail int32
	out  int32 // pattern ending at this node, or -1
	dict int32 // nearest node on the fail chain with out >= 0, or -1
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// newAC builds a matcher. Patterns are lower-cased; duplicates are ignored
// (the first index wins).
func newAC(patterns []string) *acMatcher {
	m := &acMatcher{nodes: []acNode{{next: map[byte]int32{}, out: -1, dict: -1}}, pats: patterns}
	for idx, p := range patterns {
		if p == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(p); i++ {
			c := lowerByte(p[i])
			nx, ok := m.nodes[cur].next[c]
			if !ok {
				nx = int32(len(m.nodes))
				m.nodes = append(m.nodes, acNode{next: map[byte]int32{}, out: -1, dict: -1})
				m.nodes[cur].next[c] = nx
			}
			cur = nx
		}
		if m.nodes[cur].out < 0 {
			m.nodes[cur].out = int32(idx)
		}
	}
	// breadth-first construction of fail and dict links
	queue := make([]int32, 0, len(m.nodes))
	for _, child := range m.nodes[0].next {
		m.nodes[child].fail = 0
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for c, v := range m.nodes[u].next {
			f := m.nodes[u].fail
			for {
				if nx, ok := m.nodes[f].next[c]; ok && nx != v {
					m.nodes[v].fail = nx
					break
				}
				if f == 0 {
					m.nodes[v].fail = 0
					break
				}
				f = m.nodes[f].fail
			}
			fl := m.nodes[v].fail
			if m.nodes[fl].out >= 0 {
				m.nodes[v].dict = fl
			} else {
				m.nodes[v].dict = m.nodes[fl].dict
			}
			queue = append(queue, v)
		}
	}
	return m
}

// findAll calls fn for every (possibly overlapping) occurrence.
func (m *acMatcher) findAll(text string, fn func(start, end, pat int)) {
	if m == nil || len(m.nodes) == 1 {
		return
	}
	cur := int32(0)
	for i := 0; i < len(text); i++ {
		c := lowerByte(text[i])
		for {
			if nx, ok := m.nodes[cur].next[c]; ok {
				cur = nx
				break
			}
			if cur == 0 {
				break
			}
			cur = m.nodes[cur].fail
		}
		for n := cur; n > 0; n = m.nodes[n].dict {
			if o := m.nodes[n].out; o >= 0 {
				fn(i+1-len(m.pats[o]), i+1, int(o))
			}
			if m.nodes[n].dict < 0 {
				break
			}
		}
	}
}
