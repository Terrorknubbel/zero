package chat

import (
	"crypto/ecdh"
	"fmt"
)

type Session struct {
	Name string
	localPeer *Peer
	remoteID []byte
	transport Transport
	store *Store
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
		Name:name,
		localPeer:NewPeer(name),
		transport: transport,
	}

	if dt, ok := transport.(*DummyTransport); ok {
		dt.Register(s)
	}

	return s
}

func NewSessionFromPeer(p *Peer, t Transport, st *Store) *Session {
	s := &Session{ Name: p.Name, localPeer: p, transport: t, store: st }
	if dt, ok := t.(*DummyTransport); ok { dt.Register(s) }
	return s
}

func (s *Session) StartHandshake(remote Bundle) error {
	s.remoteID = remote.IdentityPub

	initMsg := s.localPeer.InitiateSession(remote)
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
	header, nonce, cyphertext, err := s.localPeer.Encrypt(s.remoteID, plaintext)
	if err != nil {
		return err
	}

	msg := CipherMessage{Header: header, Nonce: nonce, Cipher: cyphertext}
	err = s.transport.SendCipher(s.remoteID, msg)
	if err == nil {
		s.persist()
	}
	return err
}

func (s *Session) Receive(m CipherMessage) error {
	_, plain := s.localPeer.Decrypt(s.remoteID, m.Header, m.Nonce, m.Cipher)
	fmt.Printf("[%s] ← %q\n", s.Name, plain)
	s.persist()
	return nil
}

func (s *Session) LocalBundle() Bundle {
	return s.localPeer.Bundle()
}

func (s *Session) persist() {
	if s.store == nil || s.remoteID == nil { return }
	st := s.localPeer.state(s.remoteID)
	_ = s.store.SaveSession(s.remoteID, st) // Fehler bei Demo ignorieren
}

func (s *Session) Restore(remoteID []byte, st *sessionState) {
	s.remoteID = remoteID
	s.localPeer.sess[keyOf(remoteID)] = st
}
