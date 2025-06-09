package main

import (
	"context"
	"fmt"
	"log"
	"zero/internal/chat"
)

type App struct {
	ctx context.Context
	session *chat.Session
}

func NewApp() *App {
	return &App{
		session: chat.NewSession("Alice"),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	bob := chat.NewPeer("Bob")
	err := a.session.Handshake(bob)
	if err != nil {
		log.Fatal(err)
	}

}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
