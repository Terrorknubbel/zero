package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDoubleRatchet(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Double-Ratchet Integration Suite")
}

var _ = Describe("Double-Ratchet End-to-End", func() {
	It("encrypts & decrypts messages over two sessions correctly", func() {

		alice := NewPeer("Alice")
		bob   := NewPeer("Bob")

		// ---------- Sitzung 1 : Bob initiiert ---------------------------
		initMsg := bob.InitiateSession(alice.Bundle())
		alice.AcceptSession(initMsg)
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p := bob.Encrypt(alice, []byte("Hi Alice – Bob hier."))
		Expect(string(p)).To(Equal("Hi Alice – Bob hier."))
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p = bob.Encrypt(alice, []byte("Noch eine Nachricht von Bob."))
		Expect(string(p)).To(Equal("Noch eine Nachricht von Bob."))
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p = alice.Encrypt(bob, []byte("Hallo Bob, hier ist Alice."))
		Expect(string(p)).To(Equal("Hallo Bob, hier ist Alice."))
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p = alice.Encrypt(bob, []byte("Alles angekommen."))
		Expect(string(p)).To(Equal("Alles angekommen."))
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		// ---------- Sitzung 2 : Alice initiiert -------------------------
		initMsg2 := alice.InitiateSession(bob.Bundle())
		bob.AcceptSession(initMsg2)
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p = alice.Encrypt(bob, []byte("Neue Session: Nachricht 1"))
		Expect(string(p)).To(Equal("Neue Session: Nachricht 1"))
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p = alice.Encrypt(bob, []byte("Nachricht 2"))
		Expect(string(p)).To(Equal("Nachricht 2"))
		Expect(alice.rootKey).To(Equal(bob.rootKey))

		_, p = bob.Encrypt(alice, []byte("Antwort aus neuer Session"))
		Expect(string(p)).To(Equal("Antwort aus neuer Session"))
		Expect(alice.rootKey).To(Equal(bob.rootKey))
	})
})

