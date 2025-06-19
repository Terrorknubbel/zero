package chat

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Store.EnsureIdentity", func() {
	var (
		tmpDir string
		store  *Store
		err    error
		key1   *ecdh.PrivateKey
	)

	BeforeEach(func() {
		// Temp-Dir pro Spec
		tmpDir, err = os.MkdirTemp("", "store_test_*")
		Expect(err).NotTo(HaveOccurred())

		store, err = NewStore(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("creates and reuses the same identity", func() {
		// Erstaufruf erzeugt neues IK und legt Datei an
		key1, err = store.EnsureIdentity()
		Expect(err).NotTo(HaveOccurred())
		Expect(key1).NotTo(BeNil())
		Expect(filepath.Join(tmpDir, "identity.id")).To(BeAnExistingFile())

		// Zweiter Store, derselbe Pfad → muss denselben IK & MK laden
		store2, err := NewStore(tmpDir)
		Expect(err).NotTo(HaveOccurred())

		key2, err := store2.EnsureIdentity()
		Expect(err).NotTo(HaveOccurred())
		Expect(key2.Bytes()).To(Equal(key1.Bytes()))
		Expect(store2.EnsureIdentity).NotTo(BeNil())

		// Master-Keys identisch
		Expect(storeMasterKey(store2)).To(Equal(storeMasterKey(store)))
	})

	It("stores identity encrypted (ciphertext ≠ plaintext)", func() {
		key1, err = store.EnsureIdentity()
		Expect(err).NotTo(HaveOccurred())

		raw, err := os.ReadFile(filepath.Join(tmpDir, "identity.id"))
		Expect(err).NotTo(HaveOccurred())

		nonceLen := binary.BigEndian.Uint16(raw[:2])
		ciphertext := raw[2+nonceLen:] // Header + Nonce überspringen

		// Der verschlüsselte Teil darf NICHT dem Klartext entsprechen
		Expect(ciphertext).NotTo(Equal(key1.Bytes()))
	})
})

func rand32() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}
var _ = Describe("Store.SaveSession / LoadSession", func() {

	It("persistiert und rekonstruiert einen kompletten sessionState", func() {
		tmp, _ := os.MkdirTemp("", "store_ss_*")
		defer os.RemoveAll(tmp)

		store, _ := NewStore(tmp)

		// ── künstlichen State erzeugen ────────────────────────
		curve := ecdh.X25519()

		dhSend, _ := curve.GenerateKey(rand.Reader)
		dhRecvPub := dhSend.PublicKey() // irgendein PubKey

		stOrig := &sessionState{
			rootKey:      rand32(),
			dhSendPrivKey: dhSend,
			dhRecvPubKey:  dhRecvPub,
			sendChain:     NewSymmRatchet(rand32()),
			recvChain:     NewSymmRatchet(rand32()),
		}

		remoteID := dhRecvPub.Bytes() // ID des Gegenüber

		// ── speichern & laden ────────────────────────────────
		Expect(store.SaveSession(remoteID, stOrig)).To(Succeed())

		stGot, err := store.LoadSession(remoteID)
		Expect(err).NotTo(HaveOccurred())

		// ── Feld-Vergleiche ───────────────────────────────────
		Expect(stGot.rootKey).To(Equal(stOrig.rootKey))
		Expect(stGot.dhSendPrivKey.Bytes()).To(Equal(stOrig.dhSendPrivKey.Bytes()))
		Expect(stGot.dhRecvPubKey.Bytes()).To(Equal(stOrig.dhRecvPubKey.Bytes()))
		Expect(stGot.sendChain.state).To(Equal(stOrig.sendChain.state))
		Expect(stGot.recvChain.state).To(Equal(stOrig.recvChain.state))
	})
})

// Hilfsfunktionen, damit wir auf private Felder zugreifen können
func storeMasterKey(s *Store) []byte { return s.MasterKey() }

