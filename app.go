package main

import (
	"context"
	"log"

	"zero/internal/chat"
)

type App struct {
	ctx       context.Context
	session   *chat.Session
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	if err := a.setupDemo(); err != nil {
		log.Fatal(err)
	}
}

func (a *App) setupDemo() error {
	tp := chat.NewDummyTransport()
	a.session = chat.NewSession("Alice", tp)
	bobSess := chat.NewSession("Bob", tp)

	if err := a.session.StartHandshake(bobSess.LocalBundle()); err != nil {
		return err
	}
	return bobSess.StartHandshake(a.session.LocalBundle())
}

func (a *App) SendMessage(text string) {
	err := a.session.Send([]byte(text))
	if err != nil {
		panic(err)
	}
}
