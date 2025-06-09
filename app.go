package main

import (
	"context"
	"fmt"
	"zero/internal/chat"
)

type App struct {
	ctx context.Context
	session *chat.Session
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	tp := chat.NewDummyTransport()
	a.session = chat.NewSession("Alice", tp)
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
