package chat

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"time"
)

// Manager kapselt alles, was nicht GUI-spezifisch ist.
type Manager struct {
	store      *Store
	transport  *DummyTransport

	localPeer  *Peer                 // Alice
	sessions   map[string]*Session   // key = b64(remote IK)
}

// ───────────────────────── Construction ──────────────────────────

func NewManager(storePath, peerName string) (*Manager, error) {
	st, err := NewStore(storePath)
	if err != nil {
		return nil, err
	}

	ik, _ := st.EnsureIdentity()
	m := &Manager{
		store:     st,
		transport: NewDummyTransport(),
		localPeer: NewPeerWithIdentity(peerName, ik),
		sessions:  map[string]*Session{},
	}
	return m, nil
}

// Public bootstrap for App.startup()
func (m *Manager) Initialise() error {
	if err := m.restoreAllContacts(); err != nil {
		return err
	}
	return m.addDemoBob()        // niemals fatal
}

// ───────────────────────── Persistence ───────────────────────────

func (m *Manager) restoreAllContacts() error {
    contacts, err := m.store.ListContacts()
    if err != nil {
        return err
    }

    for _, c := range contacts {
        st, err := m.store.LoadSession(c.IDPub)
        if err != nil {
            continue // noch kein state.bin
        }

        s := NewSessionFromPeer(m.localPeer, m.transport, m.store)
        s.Restore(c.IDPub, st)
        m.sessions[b64(c.IDPub)] = s
    }
    return nil
}

// ───────────────────────── Demo-Kontakt Bob ──────────────────────

func (m *Manager) addDemoBob() error {
	seed := sha256.Sum256([]byte("fixedSeedForDemo"))
	bobPriv, _ := ecdh.X25519().NewPrivateKey(seed[:])
	bobPeer    := NewPeerWithIdentity("Bob", bobPriv)
	key        := b64(bobPeer.IdentityPublicKey())

	if _, ok := m.sessions[key]; ok {
    return nil
	}
	// einmaliger Demo-Handshake:
	//   1) Alice → Bob
	aliceSess := NewSessionFromPeer(m.localPeer, m.transport, m.store)
	bobSess   := NewSessionFromPeer(bobPeer,   m.transport, m.store)

	if err := aliceSess.StartHandshake(bobSess.LocalBundle()); err != nil {
		return err
	}

	//   2) Bob → Alice  (completes the handshake on Alice’s side)
	if err := bobSess.StartHandshake(aliceSess.LocalBundle()); err != nil {
		return err
	}

	m.sessions[key] = aliceSess
	return m.store.AddContactIfMissing("Bob", bobPeer.IdentityPublicKey())
}

// ───────────────────────── External API ──────────────────────────

func (m *Manager) Contacts() ([]*Contact, error) {
	list, err := m.store.ListContacts()
	if err != nil { return nil, err }

	for _, c := range list {                 // frontend-freundliche ID
		c.ID = b64(c.IDPub)
	}
	return list, nil
}

func (m *Manager) Send(idB64, text string) error {
	log.Printf("[Manager] Send(id=%s) text=%q", idB64, text)
    sess, err := m.sessionFor(idB64)
    if err != nil {
			log.Printf("[Manager] !! Send aborted: %v", err)
        return err
    }
    return sess.Send([]byte(text))
}
func (m *Manager) Messages(idB64 string, since int64) ([]PlainMessage, error) {
	log.Printf("[Manager] Messages(id=%s since=%d)", idB64, since)
    sess, err := m.sessionFor(idB64)
    if err != nil {
				log.Printf("[Manager] !! Messages aborted: %v", err)
        return nil, err
    }
    id, _ := base64.RawURLEncoding.DecodeString(idB64)
    return sess.LoadPlainMessages(id, time.Unix(0, since))
}

// ----------------------------------------------------------------

func (m *Manager) sessionFor(idB64 string) (*Session, error) {
    log.Printf("[Manager] sessionFor(id=%s) – sessions keys: %v", idB64, keys(m.sessions))
    if s, ok := m.sessions[idB64]; ok {
        log.Printf("[Manager]  → found in-memory session for %s", idB64)
        return s, nil
     }

		log.Printf("[Manager]  → no in-memory session, trying from disk…")

    id, err := base64.RawURLEncoding.DecodeString(idB64)
    if err != nil {
        log.Printf("[Manager] !! invalid base64 id: %v", err)
        return nil, fmt.Errorf("invalid contact ID: %w", err)
    }
    if st, err := m.store.LoadSession(id); err == nil {
        log.Printf("[Manager]  → restored session from disk for %s", idB64)
        s := NewSessionFromPeer(m.localPeer, m.transport, m.store)
        s.Restore(id, st)
        m.sessions[idB64] = s
        return s, nil
    }

    log.Printf("[Manager] !! no session found for %s (disk err: %v)", idB64, err)
    return nil, fmt.Errorf("no session for peer %s", idB64)
}

func keys(m map[string]*Session) []string {
    out := make([]string, 0, len(m))
    for k := range m {
        out = append(out, k)
    }
    return out
}

