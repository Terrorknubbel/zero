package chat_test

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"zero/internal/chat"
)

var _ = Describe("Store contacts", func() {
	var (
		tmpDir string
		store  *chat.Store
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "contacts_*")
		Expect(err).NotTo(HaveOccurred())
		store, err = chat.NewStore(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("round-trips a contact & keeps it encrypted on disk", func() {
		remoteIK := []byte("IK_remote_dummy")
		contact := &chat.Contact{
			IDPub:    remoteIK,
			Name:     "Bob",
			Created:  time.Now().UTC(),
		}

		Expect(store.SaveContact(contact)).To(Succeed())

		c2, err := store.LoadContact(remoteIK)
		Expect(err).NotTo(HaveOccurred())
		Expect(c2.Name).To(Equal("Bob"))

		// Datei ist verschlüsselt (ciphertext ≠ json)
		path := tmpDir + "/contacts/" +
			base64.RawURLEncoding.EncodeToString(remoteIK) + ".json"
		raw, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())

		nonceLen := int(binary.BigEndian.Uint16(raw[:2]))
		ciphertext := raw[2+nonceLen:]
		Expect(string(ciphertext)).NotTo(ContainSubstring("\"Bob\""))
	})
})

var _ = Describe("Store contact helpers", func() {
	var (
		tmp   string
		store *chat.Store
	)

	BeforeEach(func() {
		var err error
		tmp, err = os.MkdirTemp("", "ct_*")
		Expect(err).NotTo(HaveOccurred())
		store, err = chat.NewStore(tmp)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() { os.RemoveAll(tmp) })

	It("AddContactIfMissing creates only one file for the same peer", func() {
		ik := []byte("peerKey")

		Expect(store.AddContactIfMissing("Peer-1", ik)).To(Succeed())
		Expect(store.AddContactIfMissing("Peer-1", ik)).To(Succeed())

		entries, _ := os.ReadDir(tmp + "/contacts")
		Expect(entries).To(HaveLen(1))
	})

	It("ListContacts returns all saved contacts sorted by name", func() {
		Expect(store.AddContactIfMissing("Charlie", []byte("k3"))).To(Succeed())
		Expect(store.AddContactIfMissing("Alice",   []byte("k1"))).To(Succeed())
		Expect(store.AddContactIfMissing("Bob",     []byte("k2"))).To(Succeed())

		contacts, err := store.ListContacts()
		Expect(err).NotTo(HaveOccurred())
		Expect(contacts).To(HaveLen(3))
		Expect([]string{contacts[0].Name, contacts[1].Name, contacts[2].Name}).To(Equal(
			[]string{"Alice", "Bob", "Charlie"}))
	})
})
