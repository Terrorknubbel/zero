package main

import (
	"context"
	"log"

	"zero/internal/chat"
)

type App struct {
	ctx       context.Context
	storePath string
	peerName string
	session   *chat.Session
}

func NewApp() *App {
	return &App{
		storePath: "./data", // TODO
		peerName: "Alice",
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	if err := a.setupDemo(); err != nil {
		log.Fatal(err)
	}
}

func (a *App) setupDemo() error {
	store, err := chat.NewStore(a.storePath)
	if err != nil { log.Fatal(err) }

	idPriv, err := store.EnsureIdentity()
	if err != nil { log.Fatal(err) }

	tp := chat.NewDummyTransport()

	alicePeer := chat.NewPeerWithIdentity(a.peerName, idPriv)
	a.session  = chat.NewSessionFromPeer(alicePeer, tp)

	bobSess := chat.NewSession("Bob", tp)

	if err := a.session.StartHandshake(bobSess.LocalBundle()); err != nil {
		log.Fatal(err)
	}

	return nil
}

func (a *App) SendMessage(text string) {
	err := a.session.Send([]byte(text))
	if err != nil {
		panic(err)
	}
}
