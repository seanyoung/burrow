package query

import (
	"fmt"

	"github.com/hyperledger/burrow/consensus/tendermint"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/txs"
	"github.com/tendermint/tendermint/consensus"
	ctypes "github.com/tendermint/tendermint/consensus/types"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/types"
)

type NodeView struct {
	tmNode    *tendermint.Node
	txDecoder txs.Decoder
}

func NewNodeView(tmNode *tendermint.Node, txDecoder txs.Decoder) *NodeView {
	return &NodeView{
		tmNode:    tmNode,
		txDecoder: txDecoder,
	}
}

func (nv *NodeView) PrivValidatorPublicKey() (crypto.PublicKey, error) {
	return crypto.PublicKeyFromGoCryptoPubKey(nv.tmNode.PrivValidator().GetPubKey())
}

func (nv *NodeView) NodeInfo() p2p.NodeInfo {
	return nv.tmNode.NodeInfo()
}

func (nv *NodeView) IsListening() bool {
	return nv.tmNode.Switch().IsListening()
}

func (nv *NodeView) Listeners() []p2p.Listener {
	return nv.tmNode.Switch().Listeners()
}

func (nv *NodeView) Peers() p2p.IPeerSet {
	return nv.tmNode.Switch().Peers()
}

func (nv *NodeView) BlockStore() types.BlockStoreRPC {
	return nv.tmNode.BlockStore()
}

// Pass -1 to get all available transactions
func (nv *NodeView) MempoolTransactions(maxTxs int) ([]txs.Tx, error) {
	var transactions []txs.Tx
	for _, txBytes := range nv.tmNode.MempoolReactor().Mempool.Reap(maxTxs) {
		tx, err := nv.txDecoder.DecodeTx(txBytes)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, nil
}

func (nv *NodeView) RoundState() *ctypes.RoundState {
	return nv.tmNode.ConsensusState().GetRoundState()
}

func (nv *NodeView) PeerRoundStates() ([]*ctypes.PeerRoundState, error) {
	peers := nv.tmNode.Switch().Peers().List()
	peerRoundStates := make([]*ctypes.PeerRoundState, len(peers))
	for i, peer := range peers {
		peerState, ok := peer.Get(types.PeerStateKey).(*consensus.PeerState)
		if !ok {
			return nil, fmt.Errorf("could not get PeerState for peer: %s", peer)
		}
		peerRoundStates[i] = peerState.GetRoundState()
	}
	return peerRoundStates, nil
}
