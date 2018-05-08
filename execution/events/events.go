package events

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/txs"
	"github.com/tmthrgd/go-hex"
)

func EventStringAccountInput(addr crypto.Address) string  { return fmt.Sprintf("Acc/%s/Input", addr) }
func EventStringAccountOutput(addr crypto.Address) string { return fmt.Sprintf("Acc/%s/Output", addr) }
func EventStringNameReg(name string) string               { return fmt.Sprintf("NameReg/%s", name) }
func EventStringPermissions(name string) string           { return fmt.Sprintf("Permissions/%s", name) }
func EventStringBond() string                             { return "Bond" }
func EventStringUnbond() string                           { return "Unbond" }
func EventStringRebond() string                           { return "Rebond" }

// All txs fire EventDataTx, but only CallTx might have Return or Exception
type EventDataTx struct {
	Tx        txs.Tx
	Return    []byte
	Exception string
}

// For re-use
var sendTxQuery = event.NewQueryBuilder().
	AndEquals(event.MessageTypeKey, reflect.TypeOf(&EventDataTx{}).String()).
	AndEquals(event.TxTypeKey, reflect.TypeOf(&txs.SendTx{}).String())

var callTxQuery = event.NewQueryBuilder().
	AndEquals(event.MessageTypeKey, reflect.TypeOf(&EventDataTx{}).String()).
	AndEquals(event.TxTypeKey, reflect.TypeOf(&txs.CallTx{}).String())

type eventDataTx struct {
	Tx        txs.Wrapper
	Return    []byte
	Exception string
}

func (edTx EventDataTx) MarshalJSON() ([]byte, error) {
	model := eventDataTx{
		Tx:        txs.Wrap(edTx.Tx),
		Exception: edTx.Exception,
		Return:    edTx.Return,
	}
	return json.Marshal(model)
}

func (edTx *EventDataTx) UnmarshalJSON(data []byte) error {
	model := new(eventDataTx)
	err := json.Unmarshal(data, model)
	if err != nil {
		return err
	}
	edTx.Tx = model.Tx.Unwrap()
	edTx.Return = model.Return
	edTx.Exception = model.Exception
	return nil
}

// Publish/Subscribe
func SubscribeAccountOutputSendTx(ctx context.Context, subscribable event.Subscribable, subscriber string,
	address crypto.Address, txHash []byte, ch chan<- *txs.SendTx) error {

	query := sendTxQuery.And(event.QueryForEventID(EventStringAccountOutput(address))).
		AndEquals(event.TxHashKey, hex.EncodeUpperToString(txHash))

	return event.SubscribeCallback(ctx, subscribable, subscriber, query, func(message interface{}) bool {
		if edt, ok := message.(*EventDataTx); ok {
			if sendTx, ok := edt.Tx.(*txs.SendTx); ok {
				ch <- sendTx
			}
		}
		return true
	})
}

func PublishAccountOutput(publisher event.Publisher, address crypto.Address, txHash []byte,
	tx txs.Tx, ret []byte, exception string) error {

	return event.PublishWithEventID(publisher, EventStringAccountOutput(address),
		&EventDataTx{
			Tx:        tx,
			Return:    ret,
			Exception: exception,
		},
		map[string]interface{}{
			"address":       address,
			event.TxTypeKey: reflect.TypeOf(tx).String(),
			event.TxHashKey: hex.EncodeUpperToString(txHash),
		})
}

func PublishAccountInput(publisher event.Publisher, address crypto.Address, txHash []byte,
	tx txs.Tx, ret []byte, exception string) error {

	return event.PublishWithEventID(publisher, EventStringAccountInput(address),
		&EventDataTx{
			Tx:        tx,
			Return:    ret,
			Exception: exception,
		},
		map[string]interface{}{
			"address":       address,
			event.TxTypeKey: reflect.TypeOf(tx).String(),
			event.TxHashKey: hex.EncodeUpperToString(txHash),
		})
}

func PublishNameReg(publisher event.Publisher, txHash []byte, tx *txs.NameTx) error {
	return event.PublishWithEventID(publisher, EventStringNameReg(tx.Name), &EventDataTx{Tx: tx},
		map[string]interface{}{
			"name":          tx.Name,
			event.TxTypeKey: reflect.TypeOf(tx).String(),
			event.TxHashKey: hex.EncodeUpperToString(txHash),
		})
}

func PublishPermissions(publisher event.Publisher, name string, txHash []byte, tx *txs.PermissionsTx) error {
	return event.PublishWithEventID(publisher, EventStringPermissions(name), &EventDataTx{Tx: tx},
		map[string]interface{}{
			"name":          name,
			event.TxTypeKey: reflect.TypeOf(tx).String(),
			event.TxHashKey: hex.EncodeUpperToString(txHash),
		})
}
