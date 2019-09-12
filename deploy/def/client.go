package def

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"reflect"

	hex "github.com/tmthrgd/go-hex"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/evm/abi"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/execution/names"
	"github.com/hyperledger/burrow/genesis/spec"
	"github.com/hyperledger/burrow/keys"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/permission"
	"github.com/hyperledger/burrow/rpc"
	"github.com/hyperledger/burrow/rpc/rpcevents"
	"github.com/hyperledger/burrow/rpc/rpcquery"
	"github.com/hyperledger/burrow/rpc/rpctransact"
	"github.com/hyperledger/burrow/txs"
	"github.com/hyperledger/burrow/txs/payload"
	"google.golang.org/grpc"
)

type Client struct {
	MempoolSigning bool
	ChainAddress   string
	// Memoised clients and info
	chainID               string
	timeout               time.Duration
	transactClient        rpctransact.TransactClient
	queryClient           rpcquery.QueryClient
	executionEventsClient rpcevents.ExecutionEventsClient
	keysClient            keys.KeysClient
	KeyStore              *keys.KeyStore
	AllSpecs              *abi.Spec
}

func NewClient(chain, keysDir string, mempoolSigning bool, timeout time.Duration) *Client {
	client := Client{
		ChainAddress:   chain,
		MempoolSigning: mempoolSigning,
		KeyStore:       keys.NewKeyStore(keysDir, true),
		timeout:        timeout,
	}
	return &client
}

// Connect GRPC clients using ChainURL
func (c *Client) dial(logger *logging.Logger) error {
	if c.transactClient == nil {
		conn, err := grpc.Dial(c.ChainAddress, grpc.WithInsecure())
		if err != nil {
			return err
		}
		c.transactClient = rpctransact.NewTransactClient(conn)
		c.queryClient = rpcquery.NewQueryClient(conn)
		c.executionEventsClient = rpcevents.NewExecutionEventsClient(conn)
		c.keysClient = keys.NewKeysClient(conn)

		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()

		stat, err := c.queryClient.Status(ctx, &rpcquery.StatusParam{})
		if err != nil {
			return err
		}
		c.chainID = stat.ChainID
	}
	return nil
}

func (c *Client) Transact(logger *logging.Logger) (rpctransact.TransactClient, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	return c.transactClient, err
}

func (c *Client) Query(logger *logging.Logger) (rpcquery.QueryClient, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	return c.queryClient, nil
}

func (c *Client) Events(logger *logging.Logger) (rpcevents.ExecutionEventsClient, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	return c.executionEventsClient, nil
}

func (c *Client) Status(logger *logging.Logger) (*rpc.ResultStatus, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.queryClient.Status(ctx, &rpcquery.StatusParam{})
}

func (c *Client) ParseAddress(key string, logger *logging.Logger) (crypto.Address, error) {
	address, err := crypto.AddressFromHexString(key)
	if err == nil {
		return address, nil
	}
	address, err = c.KeyStore.GetName(key)
	if err == nil {
		return address, nil
	}
	// Ask the Proxy
	err = c.dial(logger)
	if err != nil {
		return crypto.Address{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	resp, err := c.keysClient.List(ctx, &keys.ListRequest{KeyName: key})
	if err != nil {
		return crypto.Address{}, err
	}
	if len(resp.Key) != 1 {
		return crypto.Address{}, fmt.Errorf("key %s not found", key)
	}
	return crypto.AddressFromHexString(resp.Key[0].Address)
}

func (c *Client) GetAccount(address crypto.Address) (*acm.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.queryClient.GetAccount(ctx, &rpcquery.GetAccountParam{Address: address})
}

func (c *Client) GetMetadataForAccount(address crypto.Address) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	metadata, err := c.queryClient.GetMetadata(ctx, &rpcquery.GetMetadataParam{Address: &address})
	if err != nil {
		return "", err
	}

	return metadata.Metadata, nil
}

func (c *Client) GetMetadata(metahash acmstate.MetadataHash) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	var bs binary.HexBytes = metahash.Bytes()
	metadata, err := c.queryClient.GetMetadata(ctx, &rpcquery.GetMetadataParam{MetadataHash: &bs})
	if err != nil {
		return "", err
	}

	return metadata.Metadata, nil
}

func (c *Client) GetStorage(address crypto.Address, key binary.Word256) ([]byte, error) {
	val, err := c.queryClient.GetStorage(context.Background(), &rpcquery.GetStorageParam{Address: address, Key: key})
	if err != nil {
		return []byte{}, err
	}
	return val.Value, err
}

func (c *Client) GetName(name string, logger *logging.Logger) (*names.Entry, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.queryClient.GetName(ctx, &rpcquery.GetNameParam{Name: name})
}

func (c *Client) GetValidatorSet(logger *logging.Logger) (*rpcquery.ValidatorSet, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.queryClient.GetValidatorSet(ctx, &rpcquery.GetValidatorSetParam{})
}

func (c *Client) GetProposal(hash []byte, logger *logging.Logger) (*payload.Ballot, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	return c.queryClient.GetProposal(context.Background(), &rpcquery.GetProposalParam{Hash: hash})
}

func (c *Client) ListProposals(proposed bool, logger *logging.Logger) ([]*rpcquery.ProposalResult, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	stream, err := c.queryClient.ListProposals(context.Background(), &rpcquery.ListProposalsParam{Proposed: proposed})
	if err != nil {
		return nil, err
	}
	var ballots []*rpcquery.ProposalResult
	ballot, err := stream.Recv()
	for err == nil {
		ballots = append(ballots, ballot)
		ballot, err = stream.Recv()
	}
	if err == io.EOF {
		return ballots, nil
	}
	return nil, err
}

func (c *Client) SignAndBroadcast(tx payload.Payload, logger *logging.Logger) (*exec.TxExecution, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	txEnv, err := c.SignTx(tx, logger)
	if err != nil {
		return nil, err
	}
	return unifyErrors(c.BroadcastEnvelope(txEnv, logger))
}

func (c *Client) SignTx(tx payload.Payload, logger *logging.Logger) (*txs.Envelope, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	txEnv := txs.Enclose(c.chainID, tx)
	if c.MempoolSigning {
		logger.InfoMsg("Using proxy signing")
		return txEnv, nil
	}
	inputs := tx.GetInputs()
	signers := make([]acm.AddressableSigner, len(inputs))
	for i, input := range inputs {
		signers[i], err = c.KeyStore.GetKey("", input.Address)
		if err != nil {
			logger.InfoMsg("Key not available, trying proxying signing", "address", input.Address, "error", err)
			return txEnv, nil
		}
	}
	err = txEnv.Sign(signers...)
	if err != nil {
		return nil, err
	}
	return txEnv, nil
}

// Creates a keypair using attached keys service
func (c *Client) CreateKey(keyName, curveTypeString string, logger *logging.Logger) (crypto.PublicKey, error) {
	err := c.dial(logger)
	if err != nil {
		return crypto.PublicKey{}, err
	}

	curveType := crypto.CurveTypeEd25519
	if curveTypeString != "" {
		curveType, err = crypto.CurveTypeFromString(curveTypeString)
		if err != nil {
			return crypto.PublicKey{}, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.keysClient.GenerateKey(ctx, &keys.GenRequest{
		KeyName:   keyName,
		CurveType: curveType.String(),
	})
	if err == nil {
		resp, err := c.keysClient.PublicKey(ctx, &keys.PubRequest{
			Address: resp.Address,
		})
		if err != nil {
			return crypto.PublicKey{}, err
		}

		return crypto.PublicKeyFromBytes(resp.PublicKey, curveType)
	}

	// generate locally
	key, err := c.KeyStore.Gen("", curveType)
	if err != nil {
		return crypto.PublicKey{}, err
	}

	if keyName != "" {
		err = c.KeyStore.AddName(keyName, key.GetAddress())
	}

	return key.GetPublicKey(), err
}

// Broadcast payload for remote signing
func (c *Client) Broadcast(tx payload.Payload, logger *logging.Logger) (*exec.TxExecution, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return unifyErrors(c.transactClient.BroadcastTxSync(ctx, &rpctransact.TxEnvelopeParam{Payload: tx.Any()}))
}

// Broadcast envelope - can be locally signed or remote signing will be attempted
func (c *Client) BroadcastEnvelope(txEnv *txs.Envelope, logger *logging.Logger) (*exec.TxExecution, error) {
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	return unifyErrors(c.transactClient.BroadcastTxSync(ctx, &rpctransact.TxEnvelopeParam{Envelope: txEnv}))
}

func (c *Client) ParseUint64(amount string) (uint64, error) {
	if amount == "" {
		return 0, nil
	}
	return strconv.ParseUint(amount, 10, 64)
}

// Simulated call

type QueryArg struct {
	Input   string
	Address string
	Data    string
}

func (c *Client) QueryContract(arg *QueryArg, logger *logging.Logger) (*exec.TxExecution, error) {
	tx, err := c.Call(&CallArg{
		Input:   arg.Input,
		Address: arg.Address,
		Data:    arg.Data,
	}, logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return unifyErrors(c.transactClient.CallTxSim(ctx, tx))
}

// Transaction types

type GovArg struct {
	Input       string
	Native      string
	Power       string
	Sequence    string
	Permissions []string
	Roles       []string
	Address     string
	PublicKey   string
}

func (c *Client) UpdateAccount(arg *GovArg, logger *logging.Logger) (*payload.GovTx, error) {
	logger.InfoMsg("GovTx", "account", arg)
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	input, err := c.TxInput(arg.Input, arg.Native, arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}
	update := &spec.TemplateAccount{
		Permissions: arg.Permissions,
		Roles:       arg.Permissions,
	}
	if arg.Address != "" {
		addr, err := c.ParseAddress(arg.Address, logger)
		if err != nil {
			return nil, fmt.Errorf("could not parse address: %v", err)
		}
		update.Address = &addr
	}
	if arg.PublicKey != "" {
		pubKey, err := publicKeyFromString(arg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("could not parse publicKey: %v", err)
		}
		update.PublicKey = &pubKey
	} else {
		// Attempt to get public key from connected key client
		if arg.Address != "" {
			// Try key client
			pubKey, err := c.PublicKeyFromAddress(update.Address)
			if err != nil {
				logger.InfoMsg("did not get public key", "address", *update.Address)
			} else {
				update.PublicKey = &pubKey
			}
			// We can still proceed with just address set
		} else {
			return nil, fmt.Errorf("neither target address or public key were provided")
		}
	}

	_, err = permission.PermFlagFromStringList(arg.Permissions)
	if err != nil {
		return nil, fmt.Errorf("could not parse UpdateAccount permissions: %v", err)
	}

	if arg.Native != "" {
		native, err := c.ParseUint64(arg.Native)
		if err != nil {
			return nil, fmt.Errorf("could not parse native token amount: %v", err)
		}
		update.Amounts = update.Balances().Native(native)
	}
	if arg.Power != "" {
		power, err := c.ParseUint64(arg.Power)
		if err != nil {
			return nil, fmt.Errorf("could not parse native token amount: %v", err)
		}
		update.Amounts = update.Balances().Power(power)
	}
	tx := &payload.GovTx{
		Inputs:         []*payload.TxInput{input},
		AccountUpdates: []*spec.TemplateAccount{update},
	}
	return tx, nil
}

func (c *Client) PublicKeyFromAddress(address *crypto.Address) (crypto.PublicKey, error) {
	key, err := c.KeyStore.GetKey("", *address)
	if key != nil && err == nil {
		return key.PublicKey, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.keysClient.PublicKey(ctx, &keys.PubRequest{
		Address: address.String(),
	})
	if err != nil {
		return crypto.PublicKey{}, err
	}

	curveType, err := crypto.CurveTypeFromString(resp.CurveType)
	if err != nil {
		return crypto.PublicKey{}, err
	}

	return crypto.PublicKeyFromBytes(resp.PublicKey, curveType)
}

func publicKeyFromString(publicKey string) (crypto.PublicKey, error) {
	bs, err := hex.DecodeString(publicKey)
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("could not parse public key string %s as hex: %v", publicKey, err)
	}
	switch len(bs) {
	case crypto.PublicKeyLength(crypto.CurveTypeEd25519):
		return crypto.PublicKeyFromBytes(bs, crypto.CurveTypeEd25519)
	case crypto.PublicKeyLength(crypto.CurveTypeSecp256k1):
		return crypto.PublicKeyFromBytes(bs, crypto.CurveTypeSecp256k1)
	default:
		return crypto.PublicKey{}, fmt.Errorf("public key string %s has byte length %d which is not the size of either "+
			"ed25519 or compressed secp256k1 keys so cannot construct public key", publicKey, len(bs))
	}
}

type CallArg struct {
	Input    string
	Amount   string
	Sequence string
	Address  string
	Fee      string
	Gas      string
	Data     string
	WASM     string
	Metadata map[acmstate.CodeHash]string
}

func (c *Client) Call(arg *CallArg, logger *logging.Logger) (*payload.CallTx, error) {
	logger.TraceMsg("CallTx",
		"input", arg.Input,
		"amount", arg.Amount,
		"sequence", arg.Sequence,
		"address", arg.Address,
		"data", arg.Data,
		"wasm", arg.WASM)
	input, err := c.TxInput(arg.Input, arg.Amount, arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}
	var contractAddress *crypto.Address
	if arg.Address != "" {
		address, err := crypto.AddressFromHexString(arg.Address)
		if err != nil {
			return nil, err
		}
		contractAddress = &address
	}

	fee, err := c.ParseUint64(arg.Fee)
	if err != nil {
		return nil, err
	}
	gas, err := c.ParseUint64(arg.Gas)
	if err != nil {
		return nil, err
	}
	code, err := hex.DecodeString(arg.Data)
	if err != nil {
		return nil, err
	}

	wasm, err := hex.DecodeString(arg.WASM)
	if err != nil {
		return nil, err
	}

	metas := make([]*payload.ContractMeta, 0)
	for codehash, metadata := range arg.Metadata {
		metas = append(metas, &payload.ContractMeta{
			CodeHash: codehash.Bytes(),
			Meta:     metadata,
		})
	}

	tx := &payload.CallTx{
		Input:        input,
		Address:      contractAddress,
		Data:         code,
		WASM:         wasm,
		Fee:          fee,
		GasLimit:     gas,
		ContractMeta: metas,
	}

	return tx, nil
}

type SendArg struct {
	Input    string
	Amount   string
	Sequence string
	Output   string
}

func (c *Client) Send(arg *SendArg, logger *logging.Logger) (*payload.SendTx, error) {
	logger.InfoMsg("SendTx", "send", arg)
	input, err := c.TxInput(arg.Input, arg.Amount, arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}
	outputAddress, err := c.ParseAddress(arg.Output, logger)
	if err != nil {
		return nil, err
	}
	tx := &payload.SendTx{
		Inputs: []*payload.TxInput{input},
		Outputs: []*payload.TxOutput{{
			Address: outputAddress,
			Amount:  input.Amount,
		}},
	}
	return tx, nil
}

type BondArg struct {
	Input    string
	Amount   string
	Sequence string
}

func (c *Client) Bond(arg *BondArg, logger *logging.Logger) (*payload.BondTx, error) {
	logger.InfoMsg("BondTx", "account", arg)
	err := c.dial(logger)
	if err != nil {
		return nil, err
	}
	input, err := c.TxInput(arg.Input, arg.Amount, arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}
	return &payload.BondTx{
		Input: input,
	}, nil
}

type UnbondArg struct {
	Output   string
	Amount   string
	Sequence string
}

func (c *Client) Unbond(arg *UnbondArg, logger *logging.Logger) (*payload.UnbondTx, error) {
	logger.InfoMsg("UnbondTx", "account", arg)
	if err := c.dial(logger); err != nil {
		return nil, err
	}
	input, err := c.TxInput(arg.Output, arg.Amount, arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}

	tx := payload.NewUnbondTx(input.Address, input.Amount)
	tx.Input = input

	return tx, nil
}

type NameArg struct {
	Input    string
	Amount   string
	Sequence string
	Name     string
	Data     string
	Fee      string
}

func (c *Client) Name(arg *NameArg, logger *logging.Logger) (*payload.NameTx, error) {
	logger.InfoMsg("NameTx", "name", arg)
	input, err := c.TxInput(arg.Input, arg.Amount, arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}
	fee, err := c.ParseUint64(arg.Fee)
	if err != nil {
		return nil, err
	}
	tx := &payload.NameTx{
		Input: input,
		Name:  arg.Name,
		Data:  arg.Data,
		Fee:   fee,
	}
	return tx, nil
}

type PermArg struct {
	Input      string
	Sequence   string
	Action     string
	Target     string
	Permission string
	Value      string
	Role       string
}

func (c *Client) Permissions(arg *PermArg, logger *logging.Logger) (*payload.PermsTx, error) {
	logger.InfoMsg("PermsTx", "perm", arg)
	input, err := c.TxInput(arg.Input, "", arg.Sequence, true, logger)
	if err != nil {
		return nil, err
	}
	action, err := permission.PermStringToFlag(arg.Action)
	if err != nil {
		return nil, err
	}
	permArgs := permission.PermArgs{
		Action: action,
	}
	if arg.Target != "" {
		target, err := c.ParseAddress(arg.Target, logger)
		if err != nil {
			return nil, err
		}
		permArgs.Target = &target
	}
	if arg.Value != "" {
		var value bool
		switch arg.Value {
		case "true":
			value = true
		case "false":
			value = false
		default:
			return nil, fmt.Errorf("did not recognise value %s as boolean, use 'true' or 'false'", arg.Value)
		}
		permArgs.Value = &value
	}
	if arg.Permission != "" {
		perm, err := permission.PermStringToFlag(arg.Permission)
		if err != nil {
			return nil, err
		}
		permArgs.Permission = &perm
	}

	if arg.Role != "" {
		permArgs.Role = &arg.Role
	}

	tx := &payload.PermsTx{
		Input:    input,
		PermArgs: permArgs,
	}
	return tx, nil
}

func (c *Client) TxInput(inputString, amountString, sequenceString string, allowMempoolSigning bool, logger *logging.Logger) (*payload.TxInput, error) {
	var err error
	var inputAddress crypto.Address
	if inputString != "" {
		inputAddress, err = c.ParseAddress(inputString, logger)
		if err != nil {
			return nil, fmt.Errorf("TxInput(): could not obtain input address from '%s': %v", inputString, err)
		}
	}
	var amount uint64
	if amountString != "" {
		amount, err = c.ParseUint64(amountString)
		if err != nil {
			return nil, err
		}
	}
	var sequence uint64
	sequence, err = c.getSequence(sequenceString, inputAddress, c.MempoolSigning && allowMempoolSigning, logger)
	if err != nil {
		return nil, err
	}
	return &payload.TxInput{
		Address:  inputAddress,
		Amount:   amount,
		Sequence: sequence,
	}, nil
}

func (c *Client) getSequence(sequence string, inputAddress crypto.Address, mempoolSigning bool, logger *logging.Logger) (uint64, error) {
	err := c.dial(logger)
	if err != nil {
		return 0, err
	}
	if sequence == "" {
		if mempoolSigning {
			// Perform mempool signing
			return 0, nil
		}
		// Get from chain
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		acc, err := c.queryClient.GetAccount(ctx, &rpcquery.GetAccountParam{Address: inputAddress})
		if err != nil {
			return 0, err
		}
		return acc.Sequence + 1, nil
	}
	return c.ParseUint64(sequence)
}

func argMap(value interface{}) map[string]interface{} {
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	rt := rv.Type()
	fields := make(map[string]interface{})
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).Kind() == reflect.String {
			fields[rt.Field(i).Name] = rv.Field(i).String()
		}
	}
	return fields
}

// In order to safely handle a TxExecution one must check the Exception field to account for committed transaction
// (therefore having no error) that may have exceptional executions (therefore not having the normal return values)
func unifyErrors(txe *exec.TxExecution, err error) (*exec.TxExecution, error) {
	if err != nil {
		return nil, err
	}
	return txe, txe.Exception.AsError()
}
