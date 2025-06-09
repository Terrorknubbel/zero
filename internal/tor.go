package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil/ed25519"
)

const (
	dataDir  = "./tor-data"          // bleibt zwischen Starts bestehen
	keyPath  = "./onion_ed25519.key" // 64-Byte-Datei für feste Adresse
	timeout  = 2 * time.Minute       // Wartezeit für Bootstrap + Descriptor-Upload
)

func loadOrCreateKey(path string) (ed25519.KeyPair, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("unexpected key length %d (want %d)",
				len(raw), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(raw).KeyPair(), nil
	}

	key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key.PrivateKey(), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	t, err := tor.Start(nil, &tor.StartConf{DataDir: dataDir})
	if err != nil {
		log.Fatal(err)
	}
	defer t.Close()

	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	// auf Bootstrap + Descriptor-Upload warten
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	onion, err := t.Listen(ctx, &tor.ListenConf{
		Version3:    true,
		Key:         key,
		RemotePorts: []int{80}, // von außen Port 80, intern beliebig
	})
	if err != nil {
		log.Fatal(err)
	}
	defer onion.Close()

	fmt.Printf("Onion-Adresse:  http://%s.onion\n", onion.ID)

	// minimaler Handler mit statischer Antwort
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from your persistent Go Onion service!")
	})

	// HTTP-Server über Onion-Listener starten
	log.Fatal(http.Serve(onion, handler))
}

