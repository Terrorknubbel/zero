package chat

import "fmt"

type Session struct {
	Name string
	localPeer *Peer
}

func NewSession(name string) *Session {
	return &Session{
		Name:name,
		localPeer:NewPeer(name),
	}
}

func (s *Session) Handshake(dst *Peer) error {
	initMsg := s.localPeer.InitiateSession(dst.Bundle())
	dst.AcceptSession(initMsg)

	fmt.Printf("[%s] RootKey₀: %s\n", s.Name, b64(s.localPeer.rootKey))
	// TODO: Error Handling
	return nil
}

func (s *Session) Send(dst *Peer, plaintext []byte) error {
	header, nonce, cyphertext, err := s.localPeer.Encrypt(dst, plaintext)
	if err != nil {
		return err
	}

	name, plaintext := dst.Decrypt(header, nonce, cyphertext)
	fmt.Printf("[%s] → %q\n", name, plaintext)
	return nil
}
