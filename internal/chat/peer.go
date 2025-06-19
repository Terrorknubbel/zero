package chat

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/hkdf"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "log"
)

func check(err error) { if err != nil { log.Fatal(err) } }
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func hkdf32(in []byte) []byte {
    out, err := hkdf.Key(sha256.New, in, nil, "", 32)
    check(err)
    return out
}

func kdfRoot(rootKey, dhSecret []byte) (newRootKey, chainKey []byte) {
    temp := append(rootKey, dhSecret...)
    newRootKey = hkdf32(temp)
    chainKey   = hkdf32(append(dhSecret, newRootKey...))
    return
}

func encryptAEAD(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
    block, err := aes.NewCipher(key); if err != nil { return }
    gcm, err := cipher.NewGCM(block); if err != nil { return }
    nonce = make([]byte, gcm.NonceSize()); _, err = rand.Read(nonce); if err != nil { return }
    ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
    return
}
func decryptAEAD(key, nonce, ciphertext, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key); if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block); if err != nil { return nil, err }
    return gcm.Open(nil, nonce, ciphertext, aad)
}

func keyOf(pub []byte) string { return base64.StdEncoding.EncodeToString(pub) }

func (p *Peer) IdentityPublicKey() []byte { return p.identityPrivKey.PublicKey().Bytes() }

func (p *Peer) state(remoteID []byte) *sessionState {
    k := keyOf(remoteID)
    st, ok := p.sess[k]
    if !ok {
        st = &sessionState{}
        p.sess[k] = st
    }
    return st
}

type SymmRatchet struct{ state []byte }
func NewSymmRatchet(k []byte) *SymmRatchet { c := make([]byte,len(k)); copy(c,k); return &SymmRatchet{state:c} }
func (r *SymmRatchet) Next() []byte { r.state = hkdf32(r.state); return r.state }

type Peer struct {
    Name string

    // Längerfristige X3DH‑Schlüssel
    identityPrivKey      *ecdh.PrivateKey              // IK  (priv)

    // ─── Alle aktiven Sitzungen ───────────────────────
    //   Key: Remote-Identity-Public-Key (Base64 oder []byte-string)
    sess map[string]*sessionState
}

func NewPeer(name string) *Peer {
    curve := ecdh.X25519()

    idPriv, _  := curve.GenerateKey(rand.Reader)      // IK

    return &Peer{
        Name:               name,
        identityPrivKey:    idPriv,
				sess:              make(map[string]*sessionState),
    }
}

func NewPeerWithIdentity(name string, idPriv *ecdh.PrivateKey) *Peer {
	return &Peer{
		Name:             name,
		identityPrivKey:  idPriv,
		sess:             make(map[string]*sessionState),
	}
}

// Pre‑Key‑Bundle (wird veröffentlicht)
func (p *Peer) Bundle() Bundle {
    return Bundle{
        IdentityPub:  p.identityPrivKey.PublicKey().Bytes(),
    }
}

// Initiator  – startet X3DH + erster Send‑Chain‑Key
func (p *Peer) InitiateSession(remoteBundle Bundle) map[string][]byte {
    curve := ecdh.X25519()
    remoteIdPub, _  := curve.NewPublicKey(remoteBundle.IdentityPub)

		st := p.state(remoteIdPub.Bytes())

    // 2) Eigenes Ephemeral‑Key‑Pair
    ephemeralPrivKey, _ := curve.GenerateKey(rand.Reader)

    // 3) Drei X3DH‑Secrets
    dh1, _ := p.identityPrivKey.ECDH(remoteIdPub)
    dh2, _ := ephemeralPrivKey.ECDH(remoteIdPub)

    st.rootKey = hkdf32(append(dh1, dh2...))

    // 4) Start Double‑Ratchet
    st.dhSendPrivKey = ephemeralPrivKey
    st.dhRecvPubKey  = remoteIdPub

    secret, _ := st.dhSendPrivKey.ECDH(st.dhRecvPubKey)
		var chainKey []byte
    st.rootKey, chainKey = kdfRoot(st.rootKey, secret)
    st.sendChain = NewSymmRatchet(chainKey)   // send‑chain zuerst (Initiator)

    fmt.Printf("[%s] RootKey₀: %s\n", p.Name, b64(st.rootKey))

    // 5) Rückgabe an Responder
    return map[string][]byte{
        "idPub": p.identityPrivKey.PublicKey().Bytes(),
        "ekPub": ephemeralPrivKey.PublicKey().Bytes(),
    }
}

// Responder  – schließt X3DH ab + erster Recv‑Chain‑Key
func (p *Peer) AcceptSession(initMsg map[string][]byte) {
    curve := ecdh.X25519()
    remoteIdPub, _ := curve.NewPublicKey(initMsg["idPub"])
    remoteEkPub, _ := curve.NewPublicKey(initMsg["ekPub"])

		st := p.state(remoteIdPub.Bytes())

    // dieselben zwei DH‑Berechnungen, nur gespiegelt
    dh1, _ := p.identityPrivKey.ECDH(remoteIdPub)
    dh2, _ := p.identityPrivKey.ECDH(remoteEkPub)

    st.rootKey = hkdf32(append(dh1, dh2...))

    st.dhSendPrivKey = p.identityPrivKey
    st.dhRecvPubKey  = remoteEkPub

    secret, _ := st.dhSendPrivKey.ECDH(st.dhRecvPubKey)
		var chainKey []byte
    st.rootKey, chainKey = kdfRoot(st.rootKey, secret)
    st.recvChain = NewSymmRatchet(chainKey)  // Recv‑Chain zuerst (Responder)

    fmt.Printf("[%s] RootKey₀: %s\n", p.Name, b64(st.rootKey))
}

// Verschlüsselt eine Nachricht (erzeugt bei Bedarf neue Send‑Chain)
func (p *Peer) Encrypt(remoteID []byte, plaintext []byte) ([]byte, []byte, []byte, error) {
		st := p.state(remoteID)

    // Falls noch keine Send‑Chain existiert (erster Send nach Richtungswechsel)
    if st.sendChain == nil {
        curve := ecdh.X25519()
				var err error
        st.dhSendPrivKey, err = curve.GenerateKey(rand.Reader) // neues DH‑Paar
				if (err != nil) { return nil, nil, nil, err }

        secret, err := st.dhSendPrivKey.ECDH(st.dhRecvPubKey)
				if (err != nil) { return nil, nil, nil, err }

				var chainKey []byte
        st.rootKey, chainKey = kdfRoot(st.rootKey, secret)
        st.sendChain = NewSymmRatchet(chainKey)
    }

    msgKey := st.sendChain.Next()
    header := st.dhSendPrivKey.PublicKey().Bytes()

    nonce, ciphertext, err := encryptAEAD(msgKey, plaintext, header)
    fmt.Printf("[%s] → %q\n", p.Name, plaintext)
		return header, nonce, ciphertext, err
}

// Entschlüsselt eine Nachricht (dreht DH‑Ratchet, falls Header‑Key neu ist)
func (p *Peer) Decrypt(remoteID []byte, header []byte, nonce []byte, ct []byte) (string, []byte) {
		st := p.state(remoteID)
    curve := ecdh.X25519()
    peerPub, _ := curve.NewPublicKey(header)

    // 1) Neuer Header‑Key → DH‑Ratchet zuerst
    if st.dhRecvPubKey == nil || !bytes.Equal(peerPub.Bytes(), st.dhRecvPubKey.Bytes()) {
        secret, _ := st.dhSendPrivKey.ECDH(peerPub)     // DH(DHs, DHr′)
				var chainKey []byte
        st.rootKey, chainKey = kdfRoot(st.rootKey, secret)
        st.recvChain = NewSymmRatchet(chainKey)
        st.dhRecvPubKey = peerPub
        st.sendChain = nil                              // zwingt beim Gegen‑Senden neues DH
    }

    // 2) Nachrichtenschlüssel ziehen & entschlüsseln
    msgKey := st.recvChain.Next()
    plaintext, err := decryptAEAD(msgKey, nonce, ct, header); check(err)
		return p.Name, plaintext
}

