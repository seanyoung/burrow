package keys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/hyperledger/burrow/keys/common"
)

//------------------------------------------------------------
// auth

func hiddenAuth() string {
	fmt.Printf("Enter Password:")
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		common.IfExit(err)
	}
	return string(pwd)
}

//------------------------------------------------------------
// key names

// most commands require at least one of --name or --addr
func checkGetNameAddr(name, addr string) string {
	addr, err := getNameAddr(name, addr)
	common.IfExit(err)
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

type ErrConnectionRefused string

func (e ErrConnectionRefused) Error() string {
	return string(e)
}

// Call the http server
func Call(method string, args map[string]string) (string, error) {
	url := fmt.Sprintf("%s:%s/%s", KeyHost, KeyPort, method)
	b, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("Error marshaling args map: %v", err)
	}
	// log.Debugln("calling", url)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(b))
	resp, err := requestResponse(req)
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf(resp.Error)
	}
	return resp.Response, nil
}
