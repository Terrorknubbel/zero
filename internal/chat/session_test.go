package chat

import (
	"crypto/ecdh"
	"crypto/sha256"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session-Lifecycle über DummyTransport", func() {

	It("baut Handshake auf und tauscht eine Nachricht aus", func() {

    tmpDir := GinkgoT().TempDir()
    store, _ := NewStore(tmpDir)

    tp    := NewDummyTransport()
    alice := NewPeer("Alice")
    bob   := NewPeer("Bob")

		aliceSess := NewSessionFromPeer(alice, tp, store)
		bobSess   := NewSessionFromPeer(bob,   tp, store)

		// ③ Handshake (Alice → Bob)
		Expect(aliceSess.StartHandshake(bobSess.localPeer.Bundle())).To(Succeed())

		// ⑤ Nachricht senden
		Expect(aliceSess.Send([]byte("Hi Bob – Testnachricht"))).To(Succeed())

		// ⑥ Beide RootKeys für Alice↔Bob identisch?
		aliceID := aliceSess.localPeer.IdentityPublicKey()
		bobID   := bobSess.localPeer.IdentityPublicKey()

		Expect(aliceSess.localPeer.state(bobID).rootKey).
			To(Equal(bobSess.localPeer.state(aliceID).rootKey))
	})
})

var _ = Describe("Session resume ohne neuen Handshake", func() {

	It("Alice kann nach Neustart sofort wieder senden", func() {
		tmp, _ := os.MkdirTemp("", "resume_*")
		defer os.RemoveAll(tmp)

{
    store, _ := NewStore(tmp)

    // 1️⃣ persistente Alice-Identity anlegen
    aliceIK, _ := store.EnsureIdentity()
    alice := NewPeerWithIdentity("Alice", aliceIK)

    bob   := makeBob()
    dt    := NewDummyTransport()

    aSess := NewSessionFromPeer(alice, dt, store)
    bSess := NewSessionFromPeer(bob,   dt, store)

    Expect(aSess.StartHandshake(bob.Bundle())).To(Succeed())
    Expect(aSess.Send([]byte("hi"))).To(Succeed())
    Expect(bSess.localPeer.state(alice.IdentityPublicKey()).recvChain).NotTo(BeNil())
}

/* 2. Run – neue Runtime, State mit Restore */
{
    store, _ := NewStore(tmp)

    // 2️⃣ dieselbe Alice-Identity laden
    aliceIK, _ := store.EnsureIdentity()
    alice := NewPeerWithIdentity("Alice", aliceIK)

    bob   := makeBob()
    dt    := NewDummyTransport()

    aSess := NewSessionFromPeer(alice, dt, store)
    stA, _ := store.LoadSession(bob.IdentityPublicKey())
    aSess.Restore(bob.IdentityPublicKey(), stA)

    bSess := NewSessionFromPeer(bob, dt, store)
    stB, _ := store.LoadSession(alice.IdentityPublicKey())
    bSess.Restore(alice.IdentityPublicKey(), stB)

    Expect(aSess.Send([]byte("again"))).To(Succeed())
    Expect(aSess.localPeer.state(bob.IdentityPublicKey()).rootKey).
        To(Equal(bSess.localPeer.state(alice.IdentityPublicKey()).rootKey))
}
	})
})

func makeBob() *Peer {
    seed  := sha256.Sum256([]byte("bobTestSeed"))        // 32-Byte Konstante
    priv, _ := ecdh.X25519().NewPrivateKey(seed[:])
    return NewPeerWithIdentity("Bob", priv)
}

var _ = Describe("LoadPlainMessages", func() {

	It("liefert entschlüsselte Logs in richtiger Reihenfolge", func() {
		tmp, _ := os.MkdirTemp("", "msg_sess_*")
		defer os.RemoveAll(tmp)

		store, _ := NewStore(tmp)
		alice, bob := NewPeer("Alice"), NewPeer("Bob")
		dt := NewDummyTransport()

		aSess := NewSessionFromPeer(alice, dt, store)
		bSess := NewSessionFromPeer(bob,   dt, store)

		Expect(aSess.StartHandshake(bob.Bundle())).To(Succeed())

		Expect(aSess.Send([]byte("Hallo Bob"))).To(Succeed())
		time.Sleep(5 * time.Millisecond) // klarer TS-Versatz
		Expect(bSess.Send([]byte("Hi Alice"))).To(Succeed())

		msgs, err := aSess.LoadPlainMessages(bob.IdentityPublicKey(), time.Time{})
		Expect(err).NotTo(HaveOccurred())
		Expect(msgs).To(HaveLen(2))

		Expect(msgs[0].Out).To(BeTrue())               // von Alice
		Expect(msgs[0].Text).To(Equal("Hallo Bob"))
		Expect(msgs[1].Out).To(BeFalse())              // empfangen
		Expect(msgs[1].Text).To(Equal("Hi Alice"))
		Expect(msgs[0].At.Before(msgs[1].At)).To(BeTrue())
	})
})
