package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const masterKeyFile = "master.key"
const identityFile = "identity.id"
var ErrNoIdentity = errors.New("identity not found")

type Store struct {
	basePath  string
	masterKey []byte // 32 Byte AES-Schlüssel
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

func (s *Store) saveIdentity(priv *ecdh.PrivateKey) error {
    nonce, ct, err := s.encrypt(priv.Bytes())
    if err != nil { return err }

    buf := make([]byte, 2+len(nonce)+len(ct))
    binary.BigEndian.PutUint16(buf[:2], uint16(len(nonce)))
    copy(buf[2:], nonce)
    copy(buf[2+len(nonce):], ct)

    return os.WriteFile(filepath.Join(s.basePath, identityFile), buf, 0o600)
}

func (s *Store) loadIdentity() (*ecdh.PrivateKey, error) {
    raw, err := os.ReadFile(filepath.Join(s.basePath, identityFile))
    if errors.Is(err, fs.ErrNotExist) {
        return nil, ErrNoIdentity
    } else if err != nil {
        return nil, err
    }
    l := binary.BigEndian.Uint16(raw[:2])
    nonce, ct := raw[2:2+l], raw[2+l:]
    plain, err := s.decrypt(nonce, ct)
    if err != nil { return nil, err }
    return ecdh.X25519().NewPrivateKey(plain)
}

func (s *Store) EnsureIdentity() (*ecdh.PrivateKey, error) {
	id, err := s.loadIdentity()
	if err == ErrNoIdentity {
		curve := ecdh.X25519()
		id, _ = curve.GenerateKey(rand.Reader)
		if err2 := s.saveIdentity(id); err2 != nil {
			return nil, err2
		}
		return id, nil
	}
	return id, err
}

func (s *Store) MasterKey() []byte { return s.masterKey } // nur für Tests

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
