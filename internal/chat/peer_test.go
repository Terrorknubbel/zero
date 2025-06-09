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

	It("verschlüsselt und entschlüsselt alle Nachrichten korrekt über zwei Sitzungen", func() {

		alice := NewPeer("Alice")
		bob   := NewPeer("Bob")

		// ---------- Sitzung 1 – Bob initiiert --------------------------
		initMsg := bob.InitiateSession(alice.Bundle())
		alice.AcceptSession(initMsg)
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		sendAndVerify := func(src, dst *Peer, msg string) {
			header, nonce, ct, _ := src.Encrypt(dst, []byte(msg))

			_, plain := dst.Decrypt(header, nonce, ct)

			Expect(string(plain)).To(Equal(msg))
			Expect(alice.rootKey).To(Equal(bob.rootKey)) // Ratchet in Sync
		}

		sendAndVerify(bob,   alice, "Hi Alice – Bob hier.")
		sendAndVerify(bob,   alice, "Noch eine Nachricht von Bob.")
		sendAndVerify(alice, bob,   "Hallo Bob, hier ist Alice.")
		sendAndVerify(alice, bob,   "Alles angekommen.")

		// ---------- Sitzung 2 – Alice initiiert ------------------------
		initMsg2 := alice.InitiateSession(bob.Bundle())
		bob.AcceptSession(initMsg2)
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		sendAndVerify(alice, bob, "Neue Session: Nachricht 1")
		sendAndVerify(alice, bob, "Nachricht 2")
		sendAndVerify(bob,   alice, "Antwort aus neuer Session")
	})
})

