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

func (s *Session) StartHandshake(remote Bundle) error {
	s.remoteID = remote.IdentityPub

	initMsg := s.localPeer.InitiateSession(remote)
	return s.transport.SendInit(s.remoteID, initMsg)
}

func (s *Session) HandleInit(initMsg InitMessage) error {
	s.remoteID = initMsg["idPub"]
	s.localPeer.AcceptSession(initMsg)
	return nil
}

func (s *Session) Send(plaintext []byte) error {
	header, nonce, cyphertext, err := s.localPeer.Encrypt(s.remoteID, plaintext)
	if err != nil {
		return err
	}

	msg := CipherMessage{Header: header, Nonce: nonce, Cipher: cyphertext}
	return s.transport.SendCipher(s.remoteID, msg)
}

func (s *Session) Receive(m CipherMessage) error {
	_, plain := s.localPeer.Decrypt(s.remoteID, m.Header, m.Nonce, m.Cipher)
	fmt.Printf("[%s] ← %q\n", s.Name, plain)
	return nil
}

func (s *Session) LocalBundle() Bundle {
	return s.localPeer.Bundle()
}
