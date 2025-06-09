package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/ed25519"
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

type SymmRatchet struct{ state []byte }
func NewSymmRatchet(k []byte) *SymmRatchet { c := make([]byte,len(k)); copy(c,k); return &SymmRatchet{state:c} }
func (r *SymmRatchet) Next() []byte { r.state = hkdf32(r.state); return r.state }

type Peer struct {
    Name string

    // Längerfristige X3DH‑Schlüssel
    identityPrivKey      *ecdh.PrivateKey              // IK  (priv)
    signedPreKeyPriv     *ecdh.PrivateKey              // SPK (priv)
    signaturePrivKey     ed25519.PrivateKey            // Ed25519‑Signer
    signaturePubKey      ed25519.PublicKey
    signedPreKeySig      []byte                       // Sign(SPK)

    // Sitzungsspezifische X3DH‑Schlüssel
    ephemeralPrivKey     *ecdh.PrivateKey              // EK  – nur vom Initiator erzeugt

    // Double‑Ratchet State
    rootKey              []byte                       // RK

    dhSendPrivKey        *ecdh.PrivateKey              // eigenes aktuelles DH‑Paar (priv)
    dhRecvPubKey         *ecdh.PublicKey               // zuletzt empfangenes DH‑Public‑Key

    sendChain, recvChain *SymmRatchet                 // Chain‑Ratchets
}

func NewPeer(name string) *Peer {
    curve := ecdh.X25519()

    idPriv, _  := curve.GenerateKey(rand.Reader)      // IK
    spkPriv, _ := curve.GenerateKey(rand.Reader)      // SPK

    sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
    spkSig := ed25519.Sign(sigPriv, spkPriv.PublicKey().Bytes())

    return &Peer{
        Name:               name,
        identityPrivKey:    idPriv,
        signedPreKeyPriv:   spkPriv,
        signaturePrivKey:   sigPriv,
        signaturePubKey:    sigPub,
        signedPreKeySig:    spkSig,
    }
}

// Pre‑Key‑Bundle (wird veröffentlicht)
func (p *Peer) Bundle() map[string][]byte {
    return map[string][]byte{
        "idPub":  p.identityPrivKey.PublicKey().Bytes(),
        "spkPub": p.signedPreKeyPriv.PublicKey().Bytes(),
        "sigPub": p.signaturePubKey,
        "spkSig": p.signedPreKeySig,
    }
}

// Initiator  – startet X3DH + erster Send‑Chain‑Key
func (p *Peer) InitiateSession(remoteBundle map[string][]byte) map[string][]byte {
    // 1) Signatur prüfen
    if !ed25519.Verify(ed25519.PublicKey(remoteBundle["sigPub"]), remoteBundle["spkPub"], remoteBundle["spkSig"]) {
        log.Fatalf("[%s] Ungültige SPK‑Signatur", p.Name)
    }

    curve := ecdh.X25519()
    remoteIdPub, _  := curve.NewPublicKey(remoteBundle["idPub"])
    remoteSpkPub, _ := curve.NewPublicKey(remoteBundle["spkPub"])

    // 2) Eigenes Ephemeral‑Key‑Pair
    p.ephemeralPrivKey, _ = curve.GenerateKey(rand.Reader)

    // 3) Drei X3DH‑Secrets
    dh1, _ := p.identityPrivKey.ECDH(remoteSpkPub)
    dh2, _ := p.ephemeralPrivKey.ECDH(remoteIdPub)
    dh3, _ := p.ephemeralPrivKey.ECDH(remoteSpkPub)
    p.rootKey = hkdf32(bytes.Join([][]byte{dh1, dh2, dh3}, nil))

    // 4) Start Double‑Ratchet
    p.dhSendPrivKey = p.ephemeralPrivKey      // DHs = EKa
    p.dhRecvPubKey  = remoteSpkPub           // DHr = SPK_b

    secret, _ := p.dhSendPrivKey.ECDH(p.dhRecvPubKey)
		var chainKey []byte
    p.rootKey, chainKey = kdfRoot(p.rootKey, secret)
    p.sendChain = NewSymmRatchet(chainKey)   // send‑chain zuerst (Initiator)

    fmt.Printf("[%s] RootKey₀: %s\n", p.Name, b64(p.rootKey))

    // 5) Rückgabe an Responder
    return map[string][]byte{
        "idPub": p.identityPrivKey.PublicKey().Bytes(),
        "ekPub": p.ephemeralPrivKey.PublicKey().Bytes(),
    }
}

// Responder  – schließt X3DH ab + erster Recv‑Chain‑Key
func (p *Peer) AcceptSession(initMsg map[string][]byte) {
    curve := ecdh.X25519()
    remoteIdPub, _ := curve.NewPublicKey(initMsg["idPub"])
    remoteEkPub, _ := curve.NewPublicKey(initMsg["ekPub"])

    // dieselben drei DH‑Berechnungen, nur gespiegelt
    dh1, _ := p.signedPreKeyPriv.ECDH(remoteIdPub)
    dh2, _ := p.identityPrivKey.ECDH(remoteEkPub)
    dh3, _ := p.signedPreKeyPriv.ECDH(remoteEkPub)
    p.rootKey = hkdf32(bytes.Join([][]byte{dh1, dh2, dh3}, nil))

    p.dhSendPrivKey = p.signedPreKeyPriv    // DHs = SPK_b
    p.dhRecvPubKey  = remoteEkPub           // DHr = EK_a

    secret, _ := p.dhSendPrivKey.ECDH(p.dhRecvPubKey)
		var chainKey []byte
    p.rootKey, chainKey = kdfRoot(p.rootKey, secret)
    p.recvChain = NewSymmRatchet(chainKey)  // Recv‑Chain zuerst (Responder)

    fmt.Printf("[%s] RootKey₀: %s\n", p.Name, b64(p.rootKey))
}

// Verschlüsselt eine Nachricht (erzeugt bei Bedarf neue Send‑Chain)
func (p *Peer) Encrypt(dst *Peer, plaintext []byte) (string, []byte) {
    // Falls noch keine Send‑Chain existiert (erster Send nach Richtungswechsel)
    if p.sendChain == nil {
        curve := ecdh.X25519()
        p.dhSendPrivKey, _ = curve.GenerateKey(rand.Reader) // neues DH‑Paar
        secret, _ := p.dhSendPrivKey.ECDH(p.dhRecvPubKey)
				var chainKey []byte
        p.rootKey, chainKey = kdfRoot(p.rootKey, secret)
        p.sendChain = NewSymmRatchet(chainKey)
    }

    msgKey := p.sendChain.Next()
    header := p.dhSendPrivKey.PublicKey().Bytes()

    nonce, ct, _ := encryptAEAD(msgKey, plaintext, header)
    fmt.Printf("[%s] → %q\n", p.Name, plaintext)
    return dst.Decrypt(header, nonce, ct)
}

// Entschlüsselt eine Nachricht (dreht DH‑Ratchet, falls Header‑Key neu ist)
func (p *Peer) Decrypt(header, nonce, ct []byte) (string, []byte) {
    curve := ecdh.X25519()
    peerPub, _ := curve.NewPublicKey(header)

    // 1) Neuer Header‑Key → DH‑Ratchet zuerst
    if p.dhRecvPubKey == nil || !bytes.Equal(peerPub.Bytes(), p.dhRecvPubKey.Bytes()) {
        secret, _ := p.dhSendPrivKey.ECDH(peerPub)     // DH(DHs, DHr′)
				var chainKey []byte
        p.rootKey, chainKey = kdfRoot(p.rootKey, secret)
        p.recvChain = NewSymmRatchet(chainKey)
        p.dhRecvPubKey = peerPub
        p.sendChain = nil                              // zwingt beim Gegen‑Senden neues DH
    }

    // 2) Nachrichtenschlüssel ziehen & entschlüsseln
    msgKey := p.recvChain.Next()
    plaintext, err := decryptAEAD(msgKey, nonce, ct, header); check(err)
    fmt.Printf("[%s] ← %q\n", p.Name, plaintext)
		return p.Name, plaintext
}

