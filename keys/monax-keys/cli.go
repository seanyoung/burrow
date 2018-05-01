package keys

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	//"github.com/howeyc/gopass"

	"github.com/hyperledger/burrow/keys/common"

)

var (
	DefaultKeyType  = "ed25519,ripemd160"
	DefaultDir      = common.KeysPath
	DefaultHashType = "sha256"

	DefaultHost = "localhost"
	DefaultPort = "4767"
	TestPort    = "7674"
	TestAddr    = "http://" + DefaultHost + ":" + TestPort

	/* flag vars */
	//global
	LogLevel int    // currently only info level available; ignored
	KeysDir  string = ".monax-keys"
	KeyName  string
	KeyAddr  string
	KeyHost  string
	KeyPort  string

	//keygenCmd only
	NoPassword bool
	keyType    string

	//hashCmd only
	HashType string
	HexByte  bool

	// lockCmd only
	UnlockTime int // minutes

	Verbose bool
	Debug   bool
)

type ErrConnectFailed string

func (e ErrConnectFailed) Error() string {
	return string(e)
}

func ExitConnectErr(err error) {
	common.Exit(fmt.Errorf("Could not connect to monax-keys server. Start it with `monax-keys server &`. Error: %v", err))
}

func CliServer() {
	common.IfExit(StartServer(KeyHost, KeyPort))
}

func CliKeygen(keyType string, keyName string) {
	var auth string
	if !NoPassword {
		auth = hiddenAuth()
	}

	r, err := Call("gen", map[string]string{"auth": auth, "type": keyType, "name": keyName})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	LogToChannel([]byte(r))
}

func CliLock() {
	r, err := Call("lock", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

/*
func cliConvert(cmd *cobra.Command, args []string) {
	r, err := Call("mint", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}
*/
func CliUnlock() {
	auth := hiddenAuth()
	r, err := Call("unlock", map[string]string{"auth": auth, "addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

// since pubs are not saved, the key needs to be unlocked to get the pub
// TODO: save the pubkey (backwards compatibly...)
func CliPub() {
	r, err := Call("pub", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func CliSign(msg string) {
	_, addr, name := KeysDir, KeyAddr, KeyName
	r, err := Call("sign", map[string]string{"addr": addr, "name": name, "msg": msg})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func CliVerify(msg, sig, pub string) {
	r, err := Call("verify", map[string]string{"type": keyType, "pub": pub, "msg": msg, "sig": sig})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func CliHash(msg string) {
	r, err := Call("hash", map[string]string{"type": HashType, "msg": msg, "hex": fmt.Sprintf("%v", HexByte)})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func CliImport(key string, keyType string) {
	// if the key is a path, read it
	if _, err := os.Stat(key); err == nil {
		keyBytes, err := ioutil.ReadFile(key)
		key = string(keyBytes)
		common.IfExit(err)
	}

	var auth string
	if !NoPassword {
		log.Printf("Warning: Please note that this encryption will only take effect if you passed a raw private key (TODO!).")
		auth = hiddenAuth()
	}

	r, err := Call("import", map[string]string{"auth": auth, "name": KeyName, "type": keyType, "key": key})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func CliNameAdd(name, addr string) {
	r, err := Call("name", map[string]string{"name": name, "addr": addr})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func CliNameLs() {
	r, err := Call("name/ls", map[string]string{})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	names := make(map[string]string)
	common.IfExit(json.Unmarshal([]byte(r), &names))
	for n, a := range names {
		log.Printf("%s: %s\n", n, a)
	}
	LogToChannel([]byte(r))
}

func CliNameRm(name string) {
	r, err := Call("name/rm", map[string]string{"name": name})
	if _, ok := err.(ErrConnectFailed); ok {
		ExitConnectErr(err)
	}
	common.IfExit(err)
	LogToChannel([]byte(r))
}

func checkMakeDataDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}

func LogToChannel(answer []byte) {
	fmt.Fprintln(os.Stdout, string(answer))
}

