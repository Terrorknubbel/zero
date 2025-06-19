package chat

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"log"
	"time"
)

type Session struct {
	Name      string
	localPeer *Peer
	remoteID  []byte
	transport Transport
	store     *Store
}

type sessionState struct {
	// Double-Ratchet-State nur für *diesen* Remote-Peer
	rootKey              []byte
	dhSendPrivKey        *ecdh.PrivateKey
	dhRecvPubKey         *ecdh.PublicKey
	sendChain, recvChain *SymmRatchet
}

func NewSession(name string, transport Transport) *Session {
	s := &Session{
		Name:      name,
		localPeer: NewPeer(name),
		transport: transport,
	}

	if dt, ok := transport.(*DummyTransport); ok {
		dt.Register(s)
	}

	return s
}

func NewSessionFromPeer(p *Peer, t Transport, st *Store) *Session {
	s := &Session{Name: p.Name, localPeer: p, transport: t, store: st}
	if dt, ok := t.(*DummyTransport); ok {
		dt.Register(s)
	}
	return s
}

func (s *Session) StartHandshake(remote Bundle) error {
	s.remoteID = remote.IdentityPub

	initMsg := s.localPeer.InitiateSession(remote)
    log.Printf("[Session:%s] StartHandshake → sending Init to %s", s.Name, b64(s.remoteID)[:8])
    s.transport.SendInit(s.remoteID, initMsg)

	s.persist()
	return nil
}

func (s *Session) HandleInit(initMsg InitMessage) error {
	s.remoteID = initMsg["idPub"]
	s.localPeer.AcceptSession(initMsg)

	s.persist()

	return nil
}

func (s *Session) Send(plaintext []byte) error {
log.Printf("[Session:%s] Send called remote=%s plaintext=%q", s.Name, b64(s.remoteID)[:8], plaintext)
	header, nonce, cyphertext, err := s.localPeer.Encrypt(s.remoteID, plaintext)
	if err != nil {
		log.Println("  Encrypt-error:", err)
		return err
	}
	log.Printf("  hdr=%dB non=%dB ct=%dB", len(header), len(nonce), len(cyphertext))
	msg := CipherMessage{Header: header, Nonce: nonce, Cipher: cyphertext}
	err = s.transport.SendCipher(s.remoteID, msg)
	if err == nil {
		_ = s.store.AppendMessage(s.remoteID, msg, true, plaintext)
		s.persist()
	}
	return err
}

func (s *Session) Receive(m CipherMessage) error {
	log.Printf("[Session:%s] Recv hdr=%dB non=%dB ct=%dB",
        s.Name, len(m.Header), len(m.Nonce), len(m.Cipher))
	_, plain := s.localPeer.Decrypt(s.remoteID, m.Header, m.Nonce, m.Cipher)
	fmt.Printf("[%s] ← %q\n", s.Name, plain)
	_ = s.store.AppendMessage(s.remoteID, m, false, plain)
	s.persist()
	return nil
}

func (s *Session) LocalBundle() Bundle {
	return s.localPeer.Bundle()
}

func (s *Session) persist() {
	if s.store == nil || s.remoteID == nil {
		return
	}
	st := s.localPeer.state(s.remoteID)
	_ = s.store.SaveSession(s.remoteID, st) // Fehler bei Demo ignorieren
}

func (s *Session) Restore(remoteID []byte, st *sessionState) {
	s.remoteID = remoteID
	s.localPeer.sess[keyOf(remoteID)] = st
}

type PlainMessage struct {
	ID   string    `json:"id"`
	At   time.Time `json:"at"`
	Out  bool      `json:"out"`
	Text string    `json:"text"`
}

func (s *Session) LoadPlainMessages(remoteID []byte, since time.Time) ([]PlainMessage, error) {
 log.Printf("[Session:%s] LoadPlainMessages since=%s", s.Name, since)
	raw, err := s.store.LoadMessages(remoteID, since)
	if err != nil {
		log.Println("  LoadMessages-error:", err)
		return nil, err
	}
log.Printf("  got %d cipher frames", len(raw))
	var out []PlainMessage
	for _, mm := range raw {
		txt := mm.Plain

		out = append(out, PlainMessage{
			ID: base64.RawURLEncoding.EncodeToString(mm.Header) +
				base64.RawURLEncoding.EncodeToString(mm.Nonce),
			At:   mm.TS,
			Out:  mm.Out,
			Text: txt,
		})
	}
	return out, nil
}

func (s *Session) LocalPeer() *Peer { return s.localPeer }
func (s *Session) RemoteID() []byte { return s.remoteID }
