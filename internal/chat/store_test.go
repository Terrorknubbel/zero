package chat_test

import (
	"crypto/ecdh"
	"encoding/binary"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"zero/internal/chat"
)

var _ = Describe("Store.EnsureIdentity", func() {
	var (
		tmpDir string
		store  *chat.Store
		err    error
		key1   *ecdh.PrivateKey
	)

	BeforeEach(func() {
		// Temp-Dir pro Spec
		tmpDir, err = os.MkdirTemp("", "store_test_*")
		Expect(err).NotTo(HaveOccurred())

		store, err = chat.NewStore(tmpDir)
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
		store2, err := chat.NewStore(tmpDir)
		Expect(err).NotTo(HaveOccurred())

		key2, err := store2.EnsureIdentity()
		Expect(err).NotTo(HaveOccurred())
		Expect(key2.Bytes()).To(Equal(key1.Bytes()))
		Expect(store2.EnsureIdentity).NotTo(BeNil())

		// Master-Keys identisch
		Expect(store2MasterKey(store2)).To(Equal(storeMasterKey(store)))
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

// Hilfsfunktionen, damit wir auf private Felder zugreifen können
func storeMasterKey(s *chat.Store) []byte { return s.MasterKey() }
func store2MasterKey(s *chat.Store) []byte { return s.MasterKey() }

