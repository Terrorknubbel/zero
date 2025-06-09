package chat

import "fmt"

// Payload‐Typen ----------------------------------------------------------------

// InitMessage wird beim X3DH-Handshake verschickt.
type InitMessage map[string][]byte // (EKa, IK_a usw.)

// CipherMessage ist eine verschlüsselte Ratchet‐Nachricht.
type CipherMessage struct {
	Header []byte
	Nonce  []byte
	Cipher []byte
}

// Transport-Interface ---------------------------------------------------------

// Transport sorgt NUR für die Zustellung.  Er weiß nichts von Schlüsseln.
type Transport interface {
	SendInit(toID []byte, msg InitMessage) error
	SendCipher(toID []byte, msg CipherMessage) error
}

// DummyTransport leitet alles direkt an registrierte Sessions weiter.
// Später ersetzt du das durch eine Tor-Implementierung.
type DummyTransport struct {
	lookup map[string]*Session // key = b64(identityPub)
}

func NewDummyTransport() *DummyTransport {
	return &DummyTransport{lookup: make(map[string]*Session)}
}

func (t *DummyTransport) Register(sess *Session) {
	k := b64(sess.localPeer.IdentityPublicKey())
	t.lookup[k] = sess
}

// Handshake-Nachricht zustellen
func (t *DummyTransport) SendInit(toID []byte, msg InitMessage) error {
	dst, ok := t.lookup[b64(toID)]
	if !ok {
		return fmt.Errorf("unknown peer")
	}
	return dst.HandleInit(msg)
}

// Ciphertext zustellen
func (t *DummyTransport) SendCipher(toID []byte, m CipherMessage) error {
	dst, ok := t.lookup[b64(toID)]
	if !ok {
		return fmt.Errorf("unknown peer")
	}
	return dst.Receive(m)
}
