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
	a.session = chat.NewSessionFromPeer(alicePeer, a.transport)

	return nil
}

func (a *App) setupDemo() error {
	curve := ecdh.X25519()
	seed := sha256.Sum256([]byte("fixedSeedForDemo"))
	bobPriv, _ := curve.NewPrivateKey(seed[:])

	bobPeer := chat.NewPeerWithIdentity("Bob", bobPriv)
	bobSess := chat.NewSessionFromPeer(bobPeer, a.transport)

	if err := a.session.StartHandshake(bobSess.LocalBundle()); err != nil {
		return err
	}

	return a.store.AddContactIfMissing("Bob", bobPeer.IdentityPublicKey())
}

func (a *App) SendMessage(text string) {
	if err := a.session.Send([]byte(text)); err != nil {
		log.Println("send failed:", err)
	}
}

func (a *App) GetContacts() ([]*chat.Contact, error) {
	return a.store.ListContacts()
}

