package chat

import (
	"crypto/ecdh"
	"fmt"
)

type Session struct {
	Name string
	localPeer *Peer
	remotePeer *Peer
	remoteID []byte
}

type sessionState struct {
    // Double-Ratchet-State nur für *diesen* Remote-Peer
    rootKey              []byte
    dhSendPrivKey        *ecdh.PrivateKey
    dhRecvPubKey         *ecdh.PublicKey
    sendChain, recvChain *SymmRatchet
}

func NewSession(name string) *Session {
	return &Session{
		Name:name,
		localPeer:NewPeer(name),
	}
}

func (s *Session) Handshake(dst *Peer) error {
	s.remotePeer = dst
	s.remoteID = dst.IdentityPublicKey()

	initMsg := s.localPeer.InitiateSession(dst.Bundle())
	dst.AcceptSession(initMsg)

	fmt.Printf("[%s] RootKey₀: %s\n", s.Name, b64(s.localPeer.state(s.remoteID).rootKey))
	// TODO: Error Handling
	return nil
}

func (s *Session) Send(plaintext []byte) error {
	header, nonce, cyphertext, err := s.localPeer.Encrypt(s.remoteID, plaintext)
	if err != nil {
		return err
	}

	name, plaintext := s.remotePeer.Decrypt(s.localPeer.IdentityPublicKey(), header, nonce, cyphertext)
	fmt.Printf("[%s] → %q\n", name, plaintext)
	return nil
}
