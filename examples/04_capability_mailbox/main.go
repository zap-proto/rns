// Example 04 — capability-passing mailbox.
//
//	go run ./examples/04_capability_mailbox
//
// Demonstrates the ZAP capability model in pure Go: an Owner holds a
// Mailbox. The Owner can hand out two kinds of references:
//
//   - PostCap — holder may post(msg). Cannot read.
//   - ReadCap — holder may read(). Cannot post.
//
// Neither cap reveals the underlying mailbox. The Owner can revoke
// any cap at any time without rotating identities — the cap stops
// working immediately.
//
// In real ZAP RPC the capabilities are *transferable over the wire*:
// you can ship a PostCap to a third peer and they can post into the
// original Owner's mailbox without ever holding the Owner's identity
// or the ReadCap.
package main

import (
	"errors"
	"fmt"
	"sync"
)

// ─── Capability scaffold ─────────────────────────────────────────────

type capability struct {
	id      uint64
	revoked bool
}

// ─── Mailbox + caps ─────────────────────────────────────────────────

type Mailbox struct {
	mu       sync.Mutex
	messages []string
	caps     map[uint64]*capability
	nextID   uint64
}

func NewMailbox() *Mailbox {
	return &Mailbox{caps: make(map[uint64]*capability)}
}

// IssuePostCap returns a posting cap. Holder may Post; cannot Read.
func (m *Mailbox) IssuePostCap() *PostCap {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	c := &capability{id: m.nextID}
	m.caps[c.id] = c
	return &PostCap{mb: m, cap: c}
}

// IssueReadCap returns a reading cap. Holder may Read; cannot Post.
func (m *Mailbox) IssueReadCap() *ReadCap {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	c := &capability{id: m.nextID}
	m.caps[c.id] = c
	return &ReadCap{mb: m, cap: c}
}

// Revoke disables a cap. Subsequent calls fail with ErrRevoked.
func (m *Mailbox) Revoke(c *capability) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.caps[c.id]; ok {
		existing.revoked = true
	}
}

var ErrRevoked = errors.New("capability revoked")

type PostCap struct {
	mb  *Mailbox
	cap *capability
}

func (p *PostCap) Post(msg string) error {
	p.mb.mu.Lock()
	defer p.mb.mu.Unlock()
	if p.cap.revoked {
		return ErrRevoked
	}
	p.mb.messages = append(p.mb.messages, msg)
	return nil
}

type ReadCap struct {
	mb  *Mailbox
	cap *capability
}

func (r *ReadCap) Read() ([]string, error) {
	r.mb.mu.Lock()
	defer r.mb.mu.Unlock()
	if r.cap.revoked {
		return nil, ErrRevoked
	}
	// return a copy
	out := make([]string, len(r.mb.messages))
	copy(out, r.mb.messages)
	return out, nil
}

// ─── Demo ───────────────────────────────────────────────────────────

func main() {
	mb := NewMailbox()

	postCap1 := mb.IssuePostCap()
	postCap2 := mb.IssuePostCap()
	readCap := mb.IssueReadCap()

	fmt.Println("== Capability mailbox demo ==")

	// Two unrelated peers each got a PostCap. Neither can read.
	check("alice posts", postCap1.Post("hello from alice"))
	check("bob posts", postCap2.Post("hi mom"))

	// The Owner's reader sees both — alice + bob can't see each other.
	msgs, _ := readCap.Read()
	fmt.Printf("owner reads %d messages: %v\n", len(msgs), msgs)

	// Alice's cap gets revoked — she can no longer post.
	mb.Revoke(postCap1.cap)
	if err := postCap1.Post("alice tries again"); err == ErrRevoked {
		fmt.Println("✓ alice's revoked cap rejected: capability revoked")
	} else {
		fmt.Printf("FAILURE: revoked alice still posted: %v\n", err)
	}

	// Bob keeps working — independent cap.
	check("bob still posts", postCap2.Post("bob is fine"))

	// Owner reads — alice's first message stayed (revocation is forward-only),
	// alice's second never landed, bob's two posts are there.
	msgs, _ = readCap.Read()
	fmt.Printf("\nfinal mailbox contents (%d):\n", len(msgs))
	for i, m := range msgs {
		fmt.Printf("  [%d] %s\n", i, m)
	}

	fmt.Println()
	fmt.Println("This is the cap model:")
	fmt.Println("  - distinct caps for distinct rights (post vs read)")
	fmt.Println("  - holders can use but cannot forge or escalate")
	fmt.Println("  - owner can revoke without changing identity")
	fmt.Println("  - over the wire these would be ZAP capability references,")
	fmt.Println("    transferable to third parties without disclosing")
	fmt.Println("    the underlying mailbox or the owner's keys.")
}

func check(label string, err error) {
	if err != nil {
		fmt.Printf("FAILURE: %s: %v\n", label, err)
		return
	}
	fmt.Printf("✓ %s\n", label)
}
