package chat

import (
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
