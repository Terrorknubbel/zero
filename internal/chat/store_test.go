package chat

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"time"

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

var _ = Describe("Store.AppendMessage / LoadMessages", func() {

	It("appends, retrieves & keeps messages encrypted on disk", func() {
		tmp, _ := os.MkdirTemp("", "store_msg_*")
		defer os.RemoveAll(tmp)

		store, _ := NewStore(tmp)

		remoteID := []byte("peer-id-dummy") // Datei-Name basiert auf base64(ID)

		// Zwei Dummy-Nachrichten erstellen
		m1 := CipherMessage{Header: []byte("hdr-1"), Nonce: []byte("n1"), Cipher: []byte("cipher-1")}
		m2 := CipherMessage{Header: []byte("hdr-2"), Nonce: []byte("n2"), Cipher: []byte("cipher-2")}

		Expect(store.AppendMessage(remoteID, m1, true, []byte("cipher-1"))).To(Succeed())  // outgoing
		time.Sleep(10 * time.Millisecond)                               // klarer TS-Abstand
		Expect(store.AppendMessage(remoteID, m2, false, []byte("cipher-2"))).To(Succeed()) // incoming

		// ─── Laden ohne Filter ───────────────────────────────
		msgs, err := store.LoadMessages(remoteID, time.Time{})
		Expect(err).NotTo(HaveOccurred())
		Expect(msgs).To(HaveLen(2))

		Expect(msgs[0].Out).To(BeTrue())
		Expect(msgs[0].Header).To(Equal(m1.Header))
		Expect(msgs[1].Out).To(BeFalse())
		Expect(msgs[1].Cipher).To(Equal(m2.Cipher))
		Expect(msgs[0].TS.Before(msgs[1].TS)).To(BeTrue())

		// ─── since-Filter (nur die 2. Nachricht) ─────────────
		since := msgs[1].TS.Add(-1 * time.Nanosecond)
		onlyLast, _ := store.LoadMessages(remoteID, since)
		Expect(onlyLast).To(HaveLen(1))
		Expect(onlyLast[0].Header).To(Equal(m2.Header))

		// ─── Datei ist verschlüsselt (klartext darf nicht vorkommen) ─
		raw, err := os.ReadFile(filepath.Join(tmp, "msgs", b64Name(remoteID)+".log"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).NotTo(ContainSubstring("hdr-1"))   // Header im Klartext?
		Expect(string(raw)).NotTo(ContainSubstring("cipher-2")) // Cipher-Payload im Klartext?
	})
})

// Hilfsfunktionen, damit wir auf private Felder zugreifen können
func storeMasterKey(s *Store) []byte { return s.MasterKey() }

