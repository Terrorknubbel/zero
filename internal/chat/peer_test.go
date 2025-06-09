package chat

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDoubleRatchet(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Double-Ratchet Integration Suite")
}

var _ = Describe("Double-Ratchet End-to-End (Encrypt/Decrypt API)", func() {
	It("encrypts and decrypts all messages correctly over two sessions", func() {

		alice := NewPeer("Alice")
		bob   := NewPeer("Bob")

		aliceID := alice.IdentityPublicKey()
		bobID   := bob.IdentityPublicKey()

		/* ── Sitzung 1: Bob initiiert ─────────────────────────────── */
		init1 := bob.InitiateSession(alice.Bundle())
		alice.AcceptSession(init1)

		Expect(alice.state(bobID).rootKey).To(Equal(bob.state(aliceID).rootKey))

		sendAndVerify := func(src, dst *Peer, msg string) {
			header, nonce, ct, _ := src.Encrypt(dst.IdentityPublicKey(), []byte(msg))
			_, plain := dst.Decrypt(src.IdentityPublicKey(), header, nonce, ct)

			Expect(plain).To(Equal([]byte(msg)))
			Expect(src.state(dst.IdentityPublicKey()).rootKey).
				To(Equal(dst.state(src.IdentityPublicKey()).rootKey))
		}

		sendAndVerify(bob,   alice, "Hi Alice – Bob hier.")
		sendAndVerify(bob,   alice, "Noch eine Nachricht von Bob.")
		sendAndVerify(alice, bob,   "Hallo Bob, hier ist Alice.")
		sendAndVerify(alice, bob,   "Alles angekommen.")

		/* ── Sitzung 2: Alice initiiert ───────────────────────────── */
		init2 := alice.InitiateSession(bob.Bundle())
		bob.AcceptSession(init2)

		Expect(alice.state(bobID).rootKey).To(Equal(bob.state(aliceID).rootKey))

		sendAndVerify(alice, bob, "Neue Session: Nachricht 1")
		sendAndVerify(alice, bob, "Nachricht 2")
		sendAndVerify(bob,   alice, "Antwort aus neuer Session")
	})

	It("keeps separate ratchet sessions for each peer", func() {

		alice := NewPeer("Alice")
		bob   := NewPeer("Bob")
		tom   := NewPeer("Tom")

		aliceID := alice.IdentityPublicKey()
		bobID   := bob.IdentityPublicKey()
		tomID   := tom.IdentityPublicKey()

		/* ── Handshake mit Bob ─────────────────────────── */
		initBob := alice.InitiateSession(bob.Bundle())
		bob.AcceptSession(initBob)

		/* ── Handshake mit Tom ─────────────────────────── */
		initTom := alice.InitiateSession(tom.Bundle())
		tom.AcceptSession(initTom)

		/* ── RootKeys korrekt gespiegelt, aber unterschiedlich ───────── */
		Expect(alice.state(bobID).rootKey).To(Equal(bob.state(aliceID).rootKey))
		Expect(alice.state(tomID).rootKey).To(Equal(tom.state(aliceID).rootKey))
		Expect(alice.state(bobID).rootKey).NotTo(Equal(alice.state(tomID).rootKey))

		send := func(src, dst *Peer, dstID []byte, msg string) {
			h, n, ct, _ := src.Encrypt(dstID, []byte(msg))
			_, plain    := dst.Decrypt(src.IdentityPublicKey(), h, n, ct)
			Expect(string(plain)).To(Equal(msg))
		}

		/* ── Nachrichten an Bob ── */
		send(alice, bob, bobID, "Hi Bob")
		send(bob,   alice, aliceID, "Hi Alice (Bob)")

		/* ── Nachrichten an Tom ── */
		send(alice, tom, tomID, "Hi Tom")
		send(tom,   alice, aliceID, "Hello Alice (Tom)")

		/* ── Ratchets bleiben getrennt ──────────────── */
		Expect(alice.state(bobID).rootKey).NotTo(Equal(alice.state(tomID).rootKey))
		Expect(bob.state(aliceID).rootKey).NotTo(Equal(tom.state(aliceID).rootKey))
	})

})

