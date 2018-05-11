package keys

import (
	"fmt"

	"github.com/hyperledger/burrow/crypto"
	"github.com/tendermint/ed25519"
	tm_crypto "github.com/tendermint/go-crypto"
)

type Key struct {
	CurveType  crypto.CurveType
	Address    crypto.Address
	PrivateKey crypto.PrivateKey
}

func NewKey(typ crypto.CurveType) (*Key, error) {
	switch typ {
	case crypto.CurveTypeSecp256k1:
		return newKeySecp256k1()
	case crypto.CurveTypeEd25519:
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
		CurveType:  crypto.CurveTypeEd25519,
		Address:    pubKey.Address(),
		PrivateKey: privKey,
	}, nil
}

func (k *Key) Pubkey() []byte {
	return k.PrivateKey.PubKey().Address().Bytes()
}

func newKeySecp256k1() (*Key, error) {
	privKey := crypto.Secp256k1GeneratePrivateKey()

	pubKey, ok := privKey.PubKey().Unwrap().(tm_crypto.PubKeySecp256k1)
	if !ok {
		return nil, fmt.Errorf("unwrapped PubKey does not appear to be secp246k1")
	}

	address, err := crypto.AddressFromBytes(pubKey.Address())
	if err != nil {
		return nil, err
	}

	return &Key{
		CurveType:  crypto.CurveTypeSecp256k1,
		Address:    address,
		PrivateKey: privKey,
	}, nil
}

func NewKeyFromPriv(CurveType crypto.CurveType, PrivKeyBytes []byte) (*Key, error) {
	var privKey crypto.PrivateKey
	var err error
	switch CurveType {
	case crypto.CurveTypeEd25519:
		privKey, err = crypto.Ed25519PrivateKeyFromRawBytes(PrivKeyBytes)
	case crypto.CurveTypeSecp256k1:
		privKey, err = crypto.Secp256k1PrivateKeyFromRawBytes(PrivKeyBytes)
	default:
		err = fmt.Errorf("Unknown curve type %v", CurveType)
	}

	if err != nil {
		return nil, err
	}

	pubKey := privKey.PubKey()

	address, err := crypto.AddressFromBytes(pubKey.Address())
	if err != nil {
		return nil, err
	}

	return &Key{
		CurveType:  CurveType,
		Address:    address,
		PrivateKey: privKey,
	}, nil
}

type KeyStore interface {
	GenerateKey(passphrase string, curveType crypto.CurveType) (*Key, error)
	GetKey(passphrase string, addr []byte) (*Key, error)
	GetAllAddresses() ([][]byte, error)
	StoreKey(passphrase string, key *Key) error
	DeleteKey(passphrase string, addr []byte) error
}

func signSecp256k1(k *Key, hash []byte) ([]byte, error) {
	signature, err := k.PrivateKey.Sign(hash)
	sig, ok := signature.Unwrap().(tm_crypto.SignatureSecp256k1)
	if !ok {
		return nil, fmt.Errorf("unwrapped Signature does not appear to be secp246k1")
	}
	return signature.Bytes(), nil
}

func signEd25519(k *Key, hash []byte) ([]byte, error) {
	sig, err := k.PrivateKey.Sign(hash)
	if err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}

func verifySigSecp256k1(hash, sig, pubOG []byte) (bool, error) {
	var pubKey tm_crypto.PubKeySecp256k1
	copy(pubKey[:], pubOG)
	return pubKey.VerifyBytes(hash, tm_crypto.SignatureSecp256k1(sig).Wrap()), nil
}

func verifySigEd25519(hash, sig, pub []byte) (bool, error) {
	pubKeyBytes := new([32]byte)
	copy(pubKeyBytes[:], pub)
	sigBytes := new([64]byte)
	copy(sigBytes[:], sig)
	res := ed25519.Verify(pubKeyBytes, hash, sigBytes)
	return res, nil
}
