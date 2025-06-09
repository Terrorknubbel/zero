package chat

type Bundle struct {
	IdentityPub     []byte // IK public
	SignedPreKeyPub []byte // SPK public
	SignaturePub    []byte // Ed25519 public
	SignedPreKeySig []byte // Sign(SPK)
}
