package main

import (
	"context"

	"zero/internal/chat"
)

type App struct {
	ctx  context.Context
	mgr  *chat.Manager
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	mgr, err := chat.NewManager("./data", "Alice")
	if err != nil { panic(err) }

	if err = mgr.Initialise(); err != nil { panic(err) }
	a.mgr = mgr
}

/* --------- exportierte Wails-Methoden --------- */

func (a *App) GetContacts() ([]*chat.Contact, error) {
	return a.mgr.Contacts()
}

func (a *App) GetMessages(id string, since int64) ([]chat.PlainMessage, error) {
	return a.mgr.Messages(id, since)
}

func (a *App) SendMessage(id, text string) error {
	return a.mgr.Send(id, text)
}

