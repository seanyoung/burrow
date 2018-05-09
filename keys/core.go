package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/hyperledger/burrow/crypto"
	"github.com/tendermint/go-wire"
	"golang.org/x/crypto/ripemd160"
)

var GlobalKeystore KeyStore

func GetKey(addr []byte, passphrase string) (*Key, error) {
	// first check if the key is unlocked
	k, err := GlobalKeystore.GetKey(passphrase, addr)
	if err != nil {
		// Using unlocked key
		return nil, err
	}

	return k, nil
}

//-----

func returnDataDir(dir string) (string, error) {
	dir = path.Join(dir, "data")
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return dir, checkMakeDataDir(dir)
}

func returnNamesDir(dir string) (string, error) {
	dir = path.Join(dir, "names")
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return dir, checkMakeDataDir(dir)
}

//-----

// TODO: overwrite all mem buffers/registers?

func newKeyStore() (KeyStore, error) {
	dir, err := returnDataDir(KeysDir)
	if err != nil {
		return nil, err
	}
	return NewKeyStoreFile(dir), nil
}

//----------------------------------------------------------------
func writeKey(keyDir string, addr, keyJson []byte) ([]byte, error) {
	dir, err := returnDataDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("Failed to get keys dir: %v", err)
	}
	if err := WriteKeyFile(addr, dir, keyJson); err != nil {
		return nil, err
	}
	return addr, nil
}

func coreImport(auth, curveType, theKey string) ([]byte, error) {
	var keyStore KeyStore
	var err error

	log.Printf("Importing key. Type (%s). Encrypted (%v)\n", keyType, auth != "")

	if auth == "" {
		if keyStore, err = newKeyStore(); err != nil {
			return nil, err
		}
	} else {
		keyStore = GlobalKeystore
	}

	// TODO: unmarshal json and use auth to encrypt

	// if theKey is actually json, make sure
	// its a valid key, write to file
	if len(theKey) > 0 && theKey[:1] == "{" {
		keyJson := []byte(theKey)
		if addr := IsValidKeyJson(keyJson); addr != nil {
			return writeKey(KeysDir, addr, keyJson)
		} else {
			return nil, fmt.Errorf("invalid json key passed on command line")
		}
	}

	// else theKey is presumably a hex encoded private key
	keyBytes, err := hex.DecodeString(theKey)
	if err != nil {
		return nil, fmt.Errorf("private key is not a valid json or is invalid hex: %v", err)
	}

	curveT, err := CurveTypeFromString(curveType)
	if err != nil {
		return nil, err
	}
	key, err := NewKeyFromPriv(curveT, keyBytes)
	if err != nil {
		return nil, err
	}

	// store the new key
	if err = GlobalKeystore.StoreKey(auth, key); err != nil {
		return nil, err
	}

	return key.Address[:], nil
}

func coreKeygen(auth, curveType string) ([]byte, error) {
	log.Printf("Generating new key. Type (%s). Encrypted (%v)\n", keyType, auth != "")

	curveT, err := CurveTypeFromString(curveType)
	if err != nil {
		return nil, err
	}

	key, err := GlobalKeystore.GenerateKey(auth, curveT)
	if err != nil {
		return nil, fmt.Errorf("error generating key %s %s", keyType, err)
	}
	log.Printf("Generated new key. Address (%x). Type (%s). Encrypted (%v)\n", key.Address, key.CurveType, auth != "")
	return key.Address[:], nil
}

func coreSign(hash, addr, passphrase string) ([]byte, error) {

	hashB, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("hash is invalid hex: %s", err.Error())
	}
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}

	key, err := GetKey(addrB, passphrase)
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(hashB)
	if err != nil {
		return nil, fmt.Errorf("error signing %x using %x: %v", hashB, addrB, err)
	}
	return sig, nil
}

func coreVerify(typ, pub, hash, sig string) (result bool, err error) {
	curveT, err := CurveTypeFromString(typ)
	if err != nil {
		return result, err
	}
	hashB, err := hex.DecodeString(hash)
	if err != nil {
		return result, fmt.Errorf("hash is invalid hex: %s", err.Error())
	}
	pubB, err := hex.DecodeString(pub)
	if err != nil {
		return result, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}
	sigB, err := hex.DecodeString(sig)
	if err != nil {
		return result, fmt.Errorf("sig is invalid hex: %s", err.Error())
	}

	result, err = crypto.Verify(curveT, hashB, sigB, pubB)
	if err != nil {
		return result, fmt.Errorf("error verifying signature %x for pubkey %x: %v", sigB, pubB, err)
	}

	return
}

func corePub(passphrase, addr string) ([]byte, error) {
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}
	key, err := GetKey(addrB, passphrase)
	if err != nil {
		return nil, err
	}
	pub, err := key.Pubkey()
	if err != nil {
		return nil, fmt.Errorf("error retrieving pub key for %x: %v", addrB, err)
	}
	return pub, nil
}

func coreConvert(passphrase, addr string) ([]byte, error) {
	type privValidator struct {
		Address    []byte        `json:"address"`
		PubKey     []interface{} `json:"pub_key"`
		PrivKey    []interface{} `json:"priv_key"`
		LastHeight int           `json:"last_height"`
		LastRound  int           `json:"last_round"`
		LastStep   int           `json:"last_step"`
	}

	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}
	key, err := GetKey(addrB, passphrase)
	if err != nil {
		return nil, err
	}

	pub, err := key.Pubkey()
	if err != nil {
		return nil, err
	}

	var pubKeyWithType []interface{}
	var pubKey tmint_crypto.PubKeyEd25519
	copy(pubKey[:], pub)
	pubKeyWithType = append(pubKeyWithType, tmint_crypto.PubKeyTypeEd25519)
	pubKeyWithType = append(pubKeyWithType, pubKey)

	var privKeyWithType []interface{}
	var privKey tmint_crypto.PrivKeyEd25519
	copy(privKey[:], key.PrivateKey)
	privKeyWithType = append(privKeyWithType, tmint_crypto.PrivKeyTypeEd25519)
	privKeyWithType = append(privKeyWithType, privKey)

	privVal := &privValidator{
		Address: addrB,
		PubKey:  pubKeyWithType,
		PrivKey: privKeyWithType,
	}

	return wire.JSONBytes(privVal), nil
}

func coreHash(typ, data string, hexD bool) ([]byte, error) {
	var hasher hash.Hash
	switch typ {
	case "ripemd160":
		hasher = ripemd160.New()
	case "sha256":
		hasher = sha256.New()
	// case "sha3":
	default:
		return nil, fmt.Errorf("Unknown hash type %s", typ)
	}
	if hexD {
		d, err := hex.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("invalid hex")
		}
		hasher.Write(d)
	} else {
		io.WriteString(hasher, data)
	}
	return hasher.Sum(nil), nil
}

//----------------------------------------------------------------
// manage names for keys

func coreNameAdd(name, addr string) error {
	namesDir, err := returnNamesDir(KeysDir)
	if err != nil {
		return err
	}
	keysDir, err := returnDataDir(KeysDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path.Join(keysDir, addr)); err != nil {
		return fmt.Errorf("Unknown key %s", addr)
	}
	return ioutil.WriteFile(path.Join(namesDir, name), []byte(addr), 0600)
}

func coreNameList() (map[string]string, error) {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string)
	fs, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		b, err := ioutil.ReadFile(path.Join(dir, f.Name()))
		if err != nil {
			return nil, err
		}
		names[f.Name()] = string(b)
	}
	return names, nil
}

func coreAddrList() (map[int]string, error) {
	dir, err := returnDataDir(KeysDir)
	if err != nil {
		return nil, err
	}
	addrs := make(map[int]string)
	fs, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(fs); i++ {
		addrs[i] = fs[i].Name()
	}
	return addrs, nil
}

func coreNameRm(name string) error {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return err
	}
	return os.Remove(path.Join(dir, name))
}

func coreNameGet(name string) (string, error) {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadFile(path.Join(dir, name))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
