package chat

import (
	"fmt"
	"log"
	"sync"
)

// Payload‐Typen ----------------------------------------------------------------

// InitMessage wird beim X3DH-Handshake verschickt.
type InitMessage map[string][]byte // (EKa, IK_a usw.)

// CipherMessage ist eine verschlüsselte Ratchet‐Nachricht.
type CipherMessage struct {
	Header []byte `json:"hdr"`
	Nonce  []byte `json:"non"`
	Cipher []byte `json:"ct"`
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
    mu   sync.Mutex
    peers map[string]*Session
}

func NewDummyTransport() *DummyTransport {
    return &DummyTransport{peers: make(map[string]*Session)}
}

func (dt *DummyTransport) Register(s *Session) {
    key := string(s.LocalPeer().IdentityPublicKey())
    log.Printf("[TP] Register   key=%s", b64(s.LocalPeer().IdentityPublicKey()))
    dt.mu.Lock(); defer dt.mu.Unlock()
    dt.peers[key] = s
}

func (dt *DummyTransport) SendInit(id []byte, m InitMessage) error {
    k := string(id)
    log.Printf("[TP] SendInit   → %s  (registered=%v)",
        b64(id), dt.exists(k))
    dt.mu.Lock(); peer := dt.peers[k]; dt.mu.Unlock()
    if peer == nil {
        return fmt.Errorf("unknown peer(init)")
    }
    return peer.HandleInit(m)
}

func (dt *DummyTransport) SendCipher(id []byte, m CipherMessage) error {
    dt.mu.Lock()
    peer := dt.peers[string(id)]
    dt.mu.Unlock()

    if peer != nil {
        // Peer läuft im selben Prozess → direkt zustellen
        return peer.Receive(m)
    }

    // Peer ist offline/extern → Nachricht als „gesendet“ akzeptieren
    return nil
}

func (dt *DummyTransport) exists(k string) bool { _, ok := dt.peers[k]; return ok }
