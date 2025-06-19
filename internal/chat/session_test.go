package chat

import (
	"crypto/ecdh"
	"crypto/sha256"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session-Lifecycle über DummyTransport", func() {

	It("baut Handshake auf und tauscht eine Nachricht aus", func() {

		// ① Transport einmalig erzeugen
		tp := NewDummyTransport()

		// ② Alice- und Bob-Session registrieren
		aliceSess := NewSession("Alice", tp)
		bobSess   := NewSession("Bob", tp) // eigener State für Bob

		// ③ Handshake (Alice → Bob)
		Expect(aliceSess.StartHandshake(bobSess.localPeer.Bundle())).To(Succeed())

		// ④ Simulierter Handshake (Bob → Alice)
		Expect(bobSess.StartHandshake(aliceSess.localPeer.Bundle())).To(Succeed())

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
