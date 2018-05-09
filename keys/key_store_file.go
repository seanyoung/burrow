package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/hyperledger/burrow/crypto"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN     = 1 << 18
	scryptr     = 8
	scryptp     = 1
	scryptdkLen = 32
)

//-----------------------------------------------------------------------------
// json encodings

// addresses should be hex encoded

type plainKeyJSON struct {
	CurveType  string
	Address    string
	PrivateKey []byte
}

type cipherJSON struct {
	Salt       []byte
	Nonce      []byte
	CipherText []byte
}

type encryptedKeyJSON struct {
	CurveType string
	Address   string
	Crypto    cipherJSON
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSON{
		k.CurveType.String(),
		fmt.Sprintf("%X", k.Address),
		k.PrivateKey,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}
	// TODO: remove this
	if len(keyJSON.PrivateKey) == 0 {
		return fmt.Errorf("no private key")
	}

	Address, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	k.Address, err = crypto.AddressFromBytes(Address)
	if err != nil {
		return err
	}
	k.PrivateKey = keyJSON.PrivateKey
	k.CurveType, err = CurveTypeFromString(keyJSON.CurveType)
	return err
}

// returns the address if valid, nil otherwise
func IsValidKeyJson(j []byte) []byte {
	j1 := new(plainKeyJSON)
	e1 := json.Unmarshal(j, &j1)
	if e1 == nil {
		addr, _ := hex.DecodeString(j1.Address)
		return addr
	}

	j2 := new(encryptedKeyJSON)
	e2 := json.Unmarshal(j, &j2)
	if e2 == nil {
		addr, _ := hex.DecodeString(j2.Address)
		return addr
	}

	return nil
}

type keyStoreFile struct {
	sync.Mutex
	keysDirPath string
}

func NewKeyStoreFile(path string) KeyStore {
	return &keyStoreFile{keysDirPath: path}
}

func (ks keyStoreFile) GenerateKey(passphrase string, curveType CurveType) (key *Key, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("GenerateNewKey error: %v", r)
		}
	}()
	key, err = NewKey(curveType)
	if err != nil {
		return nil, err
	}
	err = ks.StoreKey(passphrase, key)
	return key, err
}

func (ks keyStoreFile) GetKey(passphrase string, keyAddr []byte) (*Key, error) {
	ks.Lock()
	defer ks.Unlock()
	fileContent, err := GetKeyFile(ks.keysDirPath, keyAddr)
	if err != nil {
		return nil, err
	}

	keyProtected := new(encryptedKeyJSON)
	if err = json.Unmarshal(fileContent, keyProtected); err == nil {
		return DecryptKey(passphrase, keyProtected)
	} else {
		key := new(Key)
		err = key.UnmarshalJSON(fileContent)
		return key, err
	}
}

func DecryptKey(passphrase string, keyProtected *encryptedKeyJSON) (*Key, error) {
	salt := keyProtected.Crypto.Salt
	nonce := keyProtected.Crypto.Nonce
	cipherText := keyProtected.Crypto.CipherText

	curveType, err := CurveTypeFromString(keyProtected.CurveType)
	if err != nil {
		return nil, err
	}
	authArray := []byte(passphrase)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptr, scryptp, scryptdkLen)
	if err != nil {
		return nil, err
	}
	aesBlock, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	address, err := crypto.AddressFromHexString(keyProtected.Address)
	if err != nil {
		return nil, err
	}

	return &Key{
		CurveType:  curveType,
		Address:    address,
		PrivateKey: plainText,
	}, nil
}

func (ks keyStoreFile) GetAllAddresses() (addresses [][]byte, err error) {
	ks.Lock()
	defer ks.Unlock()
	return GetAllAddresses(ks.keysDirPath)
}

func (ks keyStoreFile) StoreKey(passphrase string, key *Key) error {
	ks.Lock()
	defer ks.Unlock()
	if passphrase != "" {
		return ks.StoreKeyEncrypted(passphrase, key)
	} else {
		return ks.StoreKeyPlain(key)
	}
}

func (ks keyStoreFile) StoreKeyPlain(key *Key) (err error) {
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return err
	}
	err = WriteKeyFile(key.Address[:], ks.keysDirPath, keyJSON)
	return err
}

func (ks keyStoreFile) StoreKeyEncrypted(passphrase string, key *Key) error {
	authArray := []byte(passphrase)
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptr, scryptp, scryptdkLen)
	if err != nil {
		return err
	}

	toEncrypt := key.PrivateKey

	AES256Block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(AES256Block)
	if err != nil {
		return err
	}

	// XXX: a GCM nonce may only be used once per key ever!
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	// (dst, nonce, plaintext, extradata)
	cipherText := gcm.Seal(nil, nonce, toEncrypt, nil)

	cipherStruct := cipherJSON{
		salt,
		nonce,
		cipherText,
	}
	keyStruct := encryptedKeyJSON{
		key.CurveType.String(),
		strings.ToUpper(hex.EncodeToString(key.Address[:])),
		cipherStruct,
	}
	keyJSON, err := json.Marshal(keyStruct)
	if err != nil {
		return err
	}

	return WriteKeyFile(key.Address[:], ks.keysDirPath, keyJSON)
}

func (ks keyStoreFile) DeleteKey(passphrase string, keyAddr []byte) (err error) {
	keyDirPath := path.Join(ks.keysDirPath, strings.ToUpper(hex.EncodeToString(keyAddr)))
	err = os.RemoveAll(keyDirPath)
	return err
}

func GetKeyFile(keysDirPath string, keyAddr []byte) (fileContent []byte, err error) {
	fileName := strings.ToUpper(hex.EncodeToString(keyAddr))
	return ioutil.ReadFile(path.Join(keysDirPath, fileName, fileName))
}

func WriteKeyFile(addr []byte, keysDirPath string, content []byte) (err error) {
	addrHex := strings.ToUpper(hex.EncodeToString(addr))
	keyDirPath := path.Join(keysDirPath, addrHex)
	keyFilePath := path.Join(keyDirPath, addrHex)
	err = os.MkdirAll(keyDirPath, 0700) // read, write and dir search for user
	if err != nil {
		return err
	}
	return ioutil.WriteFile(keyFilePath, content, 0600) // read, write for user
}

func GetAllAddresses(keysDirPath string) (addresses [][]byte, err error) {
	fileInfos, err := ioutil.ReadDir(keysDirPath)
	if err != nil {
		return nil, err
	}
	addresses = make([][]byte, len(fileInfos))
	for i, fileInfo := range fileInfos {
		address, err := hex.DecodeString(fileInfo.Name())
		if err != nil {
			continue
		}
		addresses[i] = address
	}
	return addresses, err
}
