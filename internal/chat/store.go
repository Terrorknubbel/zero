package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	masterKeyFile = "master.key"
	identityFile  = "identity.id"
	contactsDir   = "contacts"
)

var (
	ErrNoIdentity = errors.New("identity not found")
	ErrNoContact = errors.New("contact not found")
	ErrNoSession = errors.New("session not found")
)

type Store struct {
	basePath  string
	masterKey []byte
}

func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}

	keyPath := filepath.Join(path, masterKeyFile)
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return &Store{basePath: path, masterKey: key}, nil
}

func (s *Store) saveIdentity(pk *ecdh.PrivateKey) error {
	buf, err := s.wrap(pk.Bytes())
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.basePath, identityFile), buf, 0o600)
}

func (s *Store) loadIdentity() (*ecdh.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(s.basePath, identityFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoIdentity
	} else if err != nil {
		return nil, err
	}

	plain, err := s.unwrap(raw)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(plain)
}

func (s *Store) EnsureIdentity() (*ecdh.PrivateKey, error) {
	id, err := s.loadIdentity()
	if err == ErrNoIdentity {
		id, _ = ecdh.X25519().GenerateKey(rand.Reader)
		if err = s.saveIdentity(id); err != nil {
			return nil, err
		}
		return id, nil
	}
	return id, err
}

func (s *Store) SaveContact(c *Contact) error {
	dir := filepath.Join(s.basePath, contactsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	raw, _ := json.Marshal(c)
	buf, err := s.wrap(raw)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, b64Name(c.IDPub)+".json"), buf, 0o600)
}

func (s *Store) LoadContact(idPub []byte) (*Contact, error) {
	raw, err := os.ReadFile(filepath.Join(s.basePath, contactsDir, b64Name(idPub)+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoContact
	} else if err != nil {
		return nil, err
	}

	plain, err := s.unwrap(raw)
	if err != nil {
		return nil, err
	}

	var c Contact
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) AddContactIfMissing(name string, idPub []byte) error {
	if _, err := s.LoadContact(idPub); err == nil {
		return nil
	} else if err != ErrNoContact {
		return err
	}

	c := &Contact{
		IDPub:   idPub,
		Name:    name,
		Created: time.Now().UTC(),
	}
	return s.SaveContact(c)
}

func (s *Store) ListContacts() ([]*Contact, error) {
	dir := filepath.Join(s.basePath, contactsDir)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var list []*Contact
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		plain, err := s.unwrap(raw)
		if err != nil {
			return nil, err
		}
		var c Contact
		if err := json.Unmarshal(plain, &c); err != nil {
			return nil, err
		}
		list = append(list, &c)
	}
	return list, nil
}

func (s *Store) wrap(plain []byte) ([]byte, error) {
	nonce, ct, err := s.encrypt(plain)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2+len(nonce)+len(ct))
	binary.BigEndian.PutUint16(buf, uint16(len(nonce)))
	copy(buf[2:], nonce)
	copy(buf[2+len(nonce):], ct)
	return buf, nil
}

func (s *Store) unwrap(buf []byte) ([]byte, error) {
	if len(buf) < 2 {
		return nil, errors.New("blob too short")
	}
	n := int(binary.BigEndian.Uint16(buf))
	if len(buf) < 2+n {
		return nil, errors.New("invalid nonce length")
	}
	return s.decrypt(buf[2:2+n], buf[2+n:])
}

func b64Name(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) encrypt(plain []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	ct = gcm.Seal(nil, nonce, plain, nil)
	return
}

func (s *Store) decrypt(nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func (s *Store) SaveSession(id []byte, st *sessionState) error {
	dir := filepath.Join(s.basePath, "sessions", b64Name(id))
	if err := os.MkdirAll(dir, 0o700); err != nil { return err }
	ps := persistState{
		Version: 1,
		RootKey: st.rootKey,
		DHSPriv: st.dhSendPrivKey.Bytes(),
		DHRPub:   st.dhRecvPubKey.Bytes(),
		SendCK:  st.sendCK(),
		RecvCK:  st.recvCK(),
	}
	raw, _ := json.Marshal(ps)
	buf, err := s.wrap(raw)
	if err != nil { return err }

	return os.WriteFile(filepath.Join(dir, "state.bin"), buf, 0o600)
}

func (s *Store) LoadSession(id []byte) (*sessionState, error) {
	path := filepath.Join(s.basePath, "sessions", b64Name(id), "state.bin")

	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) { return nil, ErrNoSession }
	if err != nil { return nil, err }
	plain, _ := s.unwrap(raw)
	var ps persistState
	if err := json.Unmarshal(plain, &ps); err != nil { return nil, err }
	if ps.Version != 1 { return nil, errors.New("unsupported version") }

	curve := ecdh.X25519()
	dhs, _ := curve.NewPrivateKey(ps.DHSPriv)
	dhr, _ := curve.NewPublicKey(ps.DHRPub)

	return &sessionState{
		rootKey:      ps.RootKey,
		dhSendPrivKey:dhs,
		dhRecvPubKey: dhr,
		sendChain:    maybeRatchet(ps.SendCK),
		recvChain:    maybeRatchet(ps.RecvCK),
	}, nil
}

// Test helper
func (s *Store) MasterKey() []byte { return s.masterKey }
