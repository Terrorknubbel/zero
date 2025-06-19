package main

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"log"

	"zero/internal/chat"
)

type App struct {
	ctx context.Context

	storePath string
	peerName  string

	store   *chat.Store
	transport *chat.DummyTransport
	session *chat.Session
}

func NewApp() *App {
	return &App{
		storePath: "./data", // TODO
		peerName:  "Alice",
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	if err := a.initCore(); err != nil {
		log.Fatal(err)
	}

	if err := a.setupDemo(); err != nil {
		log.Fatal(err)
	}
}

func (a *App) initCore() error {
	st, err := chat.NewStore(a.storePath)
	if err != nil {
		return err
	}
	a.store = st

	idPriv, err := a.store.EnsureIdentity()
	if err != nil {
		return err
	}

	a.transport = chat.NewDummyTransport()

	alicePeer := chat.NewPeerWithIdentity(a.peerName, idPriv)
	a.session = chat.NewSessionFromPeer(alicePeer, a.transport, a.store)

	contacts, _ := a.store.ListContacts()
	for _, c := range contacts {
		if st, err := a.store.LoadSession(c.IDPub); err == nil {
			s := chat.NewSessionFromPeer(alicePeer, a.transport, a.store)
			s.Restore(c.IDPub, st)
		}
	}

	return nil
}

func (a *App) setupDemo() error {
	curve := ecdh.X25519()
	seed  := sha256.Sum256([]byte("fixedSeedForDemo"))
	bobPriv, _ := curve.NewPrivateKey(seed[:])

	bobPeer := chat.NewPeerWithIdentity("Bob", bobPriv)
	bobIK   := bobPeer.IdentityPublicKey()

	// Ist schon ein Session-State gespeichert? → Demo-Handshake überspringen
	if _, err := a.store.LoadSession(bobIK); err == nil {
		return nil // alles vorhanden
	}

	bobSess := chat.NewSessionFromPeer(bobPeer, a.transport, a.store)

	if err := a.session.StartHandshake(bobSess.LocalBundle()); err != nil {
		return err
	}
	return a.store.AddContactIfMissing("Bob", bobIK)
}

func (a *App) SendMessage(text string) {
	if err := a.session.Send([]byte(text)); err != nil {
		log.Println("send failed:", err)
	}
}

func (a *App) GetContacts() ([]*chat.Contact, error) {
	return a.store.ListContacts()
}

