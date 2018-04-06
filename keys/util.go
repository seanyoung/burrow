package keys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/howeyc/gopass"
)

//------------------------------------------------------------
// auth

func hiddenAuth() string {
	fmt.Printf("Enter Password:")
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		IfExit(err)
	}
	return string(pwd)
}

//------------------------------------------------------------
// key names

// most commands require at least one of --name or --addr
func checkGetNameAddr(name, addr string) string {
	addr, err := getNameAddr(name, addr)
	IfExit(err)
	return addr
}

// return addr from name or addr
func getNameAddr(name, addr string) (string, error) {
	if name == "" && addr == "" {
		return "", fmt.Errorf("at least one of --name or --addr must be provided")
	}

	// name takes precedent if both are given
	var err error
	if name != "" {
		addr, err = coreNameGet(name)
		if err != nil {
			return "", err
		}
	}
	return strings.ToUpper(addr), nil
}

//------------------------------------------------------------
// http client

// Call the http server
func Call(method string, args map[string]string) (string, error) {
	daemonAddr := fmt.Sprintf("http://%s:%s", KeyHost, KeyPort)
	url := fmt.Sprintf("%s/%s", daemonAddr, method)
	b, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("Error marshaling args map: %v", err)
	}
	// log.Debugln("calling", url)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(b))
	r, err := requestResponse(req)
	if err != nil {
		return "", err
	}
	if r.Error != "" {
		return "", fmt.Errorf(r.Error)
	}
	return r.Response, nil
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
