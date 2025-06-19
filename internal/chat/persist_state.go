package chat

type persistState struct {
	Version byte   `json:"v"`   // aktuell 1
	RootKey []byte `json:"rk"`

	DHSPriv []byte `json:"dhs"` // send-priv
	DHRPub  []byte `json:"dhr"` // recv-pub

	SendCK []byte `json:"sc"`   // aktueller Send-Chain-Key (optional)
	RecvCK []byte `json:"rc"`   // aktueller Recv-Chain-Key (optional)
}
