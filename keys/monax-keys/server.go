package keys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/hyperledger/burrow/keys"
	"google.golang.org/grpc"
)

//------------------------------------------------------------------------
// all cli commands pass through the http server
// the server process also maintains the unlocked accounts

type KeysServer struct{}

func StartServer(host, port string) error {
	ks, err := newKeyStoreAuth()
	if err != nil {
		return err
	}

	AccountManager = NewManager(ks)

	listen, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	keys.RegisterKeysServer(grpcServer, &KeysServer{})
	return grpcServer.Serve(listen)
}

// A request is just a map of args to be json marshalled
type HTTPRequest map[string]string

// dead simple response struct
type HTTPResponse struct {
	Response string
	Error    string
}

func WriteResult(w http.ResponseWriter, result string) {
	resp := HTTPResponse{result, ""}
	b, _ := json.Marshal(resp)
	w.Write(b)
}

func WriteError(w http.ResponseWriter, err error) {
	resp := HTTPResponse{"", err.Error()}
	b, _ := json.Marshal(resp)
	w.Write(b)
}

//------------------------------------------------------------------------
// handlers

func (k *KeysServer) Gen(ctx context.Context, in *keys.GenRequest) (*keys.GenResponse, error) {
	addr, err := coreKeygen(in.Auth, in.Keytype)
	if err != nil {
		return nil, err
	}

	addrH := strings.ToUpper(hex.EncodeToString(addr))
	if in.Keyname != "" {
		err = coreNameAdd(in.Keyname, addrH)
		if err != nil {
			return nil, err
		}
	}

	return &keys.GenResponse{Address: addrH}, nil
}

func (k *KeysServer) Unlock(ctx context.Context, in *keys.UnlockRequest) (*keys.Empty, error) {
	addr, err := getNameAddr(in.Keyname, in.Address)
	if err != nil {
		return nil, err
	}

	return nil, coreUnlock(in.Auth, addr, fmt.Sprintf("%d", in.Timeout))
}

func convertMintHandler(w http.ResponseWriter, r *http.Request) {
	_, _, args, err := typeAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	addr, name := args["addr"], args["name"]
	addr, err = getNameAddr(name, addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	key, err := coreConvert(addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, string(key))
}

func lockHandler(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func (k *KeysServer) Pub(ctx context.Context, in *keys.PubRequest) (*keys.PubResponse, error) {
	addr, err := getNameAddr(in.Keyname, in.Address)
	if err != nil {
		return nil, err
	}

	pub, err := corePub(addr)
	if err != nil {
		return nil, err
	}

	return &keys.PubResponse{Pub: fmt.Sprintf("%X", pub)}, nil
}

func (k *KeysServer) Sign(ctx context.Context, in *keys.SignRequest) (*keys.SignResponse, error) {
	addr, err := getNameAddr(in.Keyname, in.Address)
	if err != nil {
		return nil, err
	}

	sig, err := coreSign(in.Message, addr)
	if err != nil {
		return nil, err
	}

	return &keys.SignResponse{Signature: fmt.Sprintf("%X", sig)}, nil
}

func (k *KeysServer) Verify(ctx context.Context, in *keys.VerifyRequest) (*keys.Empty, error) {
	if in.GetPub() == "" {
		return nil, fmt.Errorf("must provide a pubkey with the `pub` key")
	}
	if in.GetMessage() == "" {
		return nil, fmt.Errorf("must provide a message msg with the `msg` key")
	}
	if in.GetSignature() == "" {
		return nil, fmt.Errorf("must provide a signature with the `sig` key")
	}

	_, err := coreVerify(in.GetKeytype(), in.GetPub(), in.GetMessage(), in.GetSignature())

	return nil, err
}

func (k *KeysServer) Hash(ctx context.Context, in *keys.HashRequest) (*keys.HashResponse, error) {
	hash, err := coreHash(in.GetKeytype(), in.GetMessage(), in.GetHex())
	if err != nil {
		return nil, err
	}

	return &keys.HashResponse{Hash: fmt.Sprintf("%X", hash)}, nil
}

func importHandler(w http.ResponseWriter, r *http.Request) {
	typ, auth, args, err := typeAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	name, key := args["data"], args["key"]

	addr, err := coreImport(auth, typ, key)
	if err != nil {
		WriteError(w, err)
		return
	}

	if name != "" {
		if err := coreNameAdd(name, strings.ToUpper(hex.EncodeToString(addr))); err != nil {
			WriteError(w, err)
			return
		}
	}
	WriteResult(w, fmt.Sprintf("%X", addr))
}

func (k *KeysServer) List(ctx context.Context, in *keys.KeyName) (*keys.ListResponse, error) {
	names, err := coreNameList()
	if err != nil {
		return nil, err
	}

	var list []*keys.Key

	for name, addr := range names {
		list = append(list, &keys.Key{Keyname: name, Address: addr})
	}

	return &keys.ListResponse{Key: list}, nil
}

func (k *KeysServer) Remove(ctx context.Context, in *keys.KeyName) (*keys.Empty, error) {
	if in.GetKeyname() == "" {
		return nil, fmt.Errorf("please specify a name")
	}

	return nil, coreNameRm(in.GetKeyname())
}

func (k *KeysServer) Add(ctx context.Context, in *keys.AddRequest) (*keys.Empty, error) {
	if in.GetKeyname() == "" {
		return nil, fmt.Errorf("please specify a name")
	}

	if in.GetAddress() == "" {
		return nil, fmt.Errorf("please specify an address")
	}

	return nil, coreNameAdd(in.GetKeyname(), strings.ToUpper(in.GetAddress()))
}

// convenience function
func typeAuthArgs(r *http.Request) (typ string, auth string, args map[string]string, err error) {

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}

	// log.Debugln("Request body:", string(b))

	if err = json.Unmarshal(b, &args); err != nil {
		return
	}

	typ = args["type"]
	if typ == "" {
		typ = DefaultKeyType
	}

	auth = args["auth"]
	if auth == "" {
		auth = "" //DefaultAuth
	}

	return
}
