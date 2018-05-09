package keys

import (
	"fmt"

	"github.com/hyperledger/burrow/crypto"
	tm_crypto "github.com/tendermint/go-crypto"
)

type CurveType int8

const (
	CurveTypeSecp256k1 CurveType = iota
	CurveTypeEd25519
)

func (k CurveType) String() string {
	switch k {
	case CurveTypeSecp256k1:
		return "secp256k1"
	case CurveTypeEd25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

func CurveTypeFromString(s string) (CurveType, error) {
	switch s {
	case "secp256k1":
		return CurveTypeSecp256k1, nil
	case "ed25519":
		return CurveTypeEd25519, nil
	default:
		var k CurveType
		return k, ErrInvalidCurve(s)
	}
}

type ErrInvalidCurve string

func (err ErrInvalidCurve) Error() string {
	return fmt.Sprintf("invalid curve type %v", err)
}

type Key struct {
	CurveType  CurveType
	Address    crypto.Address
	PrivateKey []byte
}

func NewKey(typ CurveType) (*Key, error) {
	switch typ {
	case CurveTypeSecp256k1:
		return newKeySecp256k1()
	case CurveTypeEd25519:
		return newKeyEd25519()
	default:
		return nil, fmt.Errorf("Unknown curve type: %v", typ)
	}
}

func newKeyEd25519() (*Key, error) {
	privKey, err := crypto.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}
	pubKey := privKey.PublicKey()
	return &Key{
		CurveType:  CurveTypeEd25519,
		Address:    pubKey.Address(),
		PrivateKey: privKey.RawBytes(),
	}, nil
}

func newKeySecp256k1() (*Key, error) {
	privKey := tm_crypto.GenPrivKeySecp256k1()

	pubKey, ok := privKey.PubKey().Unwrap().(tm_crypto.PubKeySecp256k1)
	if !ok {
		return nil, fmt.Errorf("unwrapped PubKey does not appear to be secp246k1")
	}

	address, err := crypto.AddressFromBytes(pubKey.Address())
	if err != nil {
		return nil, err
	}

	return &Key{
		CurveType:  CurveTypeSecp256k1,
		Address:    address,
		PrivateKey: privKey[:],
	}, nil
}

type KeyStore interface {
	GenerateKey(passphrase string, curveType CurveType) (*Key, error)
	GetKey(passphrase string, addr []byte) (*Key, error)
	GetAllAddresses() ([][]byte, error)
	StoreKey(passphrase string, key *Key) error
	DeleteKey(passphrase string, addr []byte) error
}
