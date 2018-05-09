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

	"github.com/hyperledger/burrow/keys/protobuf"
	"google.golang.org/grpc"
)

//------------------------------------------------------------------------
// all cli commands pass through the http server
// the server process also maintains the unlocked accounts

type server struct{}

func StartServer(host, port string) error {
	ks, err := newKeyStore()
	if err != nil {
		return err
	}

	GlobalKeystore = ks

	listen, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	pbkeys.RegisterKeysServer(grpcServer, &server{})
	return grpcServer.Serve(listen)
}

// A request is just a map of args to be json marshalled
type HTTPRequest map[string]string

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

func (k *server) Gen(ctx context.Context, in *pbkeys.GenRequest) (*pbkeys.GenResponse, error) {
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

	return &pbkeys.GenResponse{Address: addrH}, nil
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
	key, err := coreConvert("", addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, string(key))
}

func lockHandler(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func (k *server) Pub(ctx context.Context, in *pbkeys.PubRequest) (*pbkeys.PubResponse, error) {
	addr, err := getNameAddr(in.Keyname, in.Address)
	if err != nil {
		return nil, err
	}

	pub, err := corePub("", addr)
	if err != nil {
		return nil, err
	}

	return &pbkeys.PubResponse{Pub: fmt.Sprintf("%X", pub)}, nil
}

func (k *server) Sign(ctx context.Context, in *pbkeys.SignRequest) (*pbkeys.SignResponse, error) {
	addr, err := getNameAddr(in.Keyname, in.Address)
	if err != nil {
		return nil, err
	}

	sig, err := coreSign("", in.Message, addr)
	if err != nil {
		return nil, err
	}

	return &pbkeys.SignResponse{Signature: fmt.Sprintf("%X", sig)}, nil
}

func (k *server) Verify(ctx context.Context, in *pbkeys.VerifyRequest) (*pbkeys.Empty, error) {
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

func (k *server) Hash(ctx context.Context, in *pbkeys.HashRequest) (*pbkeys.HashResponse, error) {
	hash, err := coreHash(in.GetKeytype(), in.GetMessage(), in.GetHex())
	if err != nil {
		return nil, err
	}

	return &pbkeys.HashResponse{Hash: fmt.Sprintf("%X", hash)}, nil
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

func (k *server) List(ctx context.Context, in *pbkeys.Name) (*pbkeys.ListResponse, error) {
	names, err := coreNameList()
	if err != nil {
		return nil, err
	}

	var list []*pbkeys.Key

	for name, addr := range names {
		list = append(list, &pbkeys.Key{Keyname: name, Address: addr})
	}

	return &pbkeys.ListResponse{Key: list}, nil
}

func (k *server) Remove(ctx context.Context, in *pbkeys.Name) (*pbkeys.Empty, error) {
	if in.GetKeyname() == "" {
		return nil, fmt.Errorf("please specify a name")
	}

	return nil, coreNameRm(in.GetKeyname())
}

func (k *server) Add(ctx context.Context, in *pbkeys.AddRequest) (*pbkeys.Empty, error) {
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
