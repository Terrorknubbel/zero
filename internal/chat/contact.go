package chat

import "time"

type Contact struct {
	IDPub    []byte    `json:"id_pub"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
}
