package observer

import (
	"bytes"
	"container/list"
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/evdatsion/btc-relayer-poly/db"
	"github.com/evdatsion/btc-relayer-poly/log"
	"github.com/evdatsion/btc-relayer-poly/utils"
	"os"
	"strconv"
	"time"
)

type BtcObConfig struct {
	NetType            string `json:"net_type"`
	BtcObLoopWaitTime  int64  `json:"btc_ob_loop_wait_time"`
	BtcObConfirmations uint32 `json:"btc_ob_confirmations"`
	BtcJsonRpcAddress  string `json:"btc_json_rpc_address"`
	User               string `json:"user"`
	Pwd                string `json:"pwd"`
	StartHeight        uint32 `json:"start_height"`
}

type BtcObserver struct {
	cli         *utils.RestCli
	NetParam    *chaincfg.Params
	conf        *BtcObConfig
	poly        *sdk.PolySdk
	hdrsRelayed *list.List
}

func NewBtcObserver(conf *BtcObConfig, cli *utils.RestCli, poly *sdk.PolySdk) *BtcObserver {
	var param *chaincfg.Params
	switch conf.NetType {
	case "test":
		param = &chaincfg.TestNet3Params
	case "sim":
		param = &chaincfg.SimNetParams
	case "regtest":
		param = &chaincfg.RegressionNetParams
	default:
		param = &chaincfg.MainNetParams
	}
	var observer BtcObserver
	observer.cli = cli
	observer.NetParam = param
	observer.conf = conf
	observer.poly = poly
	observer.hdrsRelayed = list.New()

	return &observer
}

func (observer *BtcObserver) initHdrsRelayed(hdrToCheck string, top uint32) {
	oldh, _ := chainhash.NewHashFromStr(hdrToCheck)
	observer.hdrsRelayed.PushFront(Record{
		hash:   *oldh,
		height: top,
	})
	for i := 1; i < 15; i++ {
		if top < uint32(i) {
			break
		}
		_, _, hdrToCheck, err := observer.cli.GetTxsAndHeader(top-uint32(i), 0)
		if err != nil {
			i--
			utils.Wait(utils.SleepTime * time.Second)
			continue
		}
		oldh, _ = chainhash.NewHashFromStr(hdrToCheck)
		observer.hdrsRelayed.PushFront(Record{
			hash:   *oldh,
			height: top - uint32(i),
		})
	}
}

func (observer *BtcObserver) Listen(cc chan *utils.CrossChainItem, hc chan *utils.Header) {
	top, oldHash, err := utils.GetCurrHeightFromPoly(observer.poly)
	if err != nil {
		switch err.(type) {
		case client.PostErr:
			log.Errorf("[BtcObserver] post-req to orchain err: %v", err)
			utils.Wait(time.Second * utils.SleepTime)
		default:
			log.Fatalf("[BtcObserver] failed to get curr-height: %v", err)
			os.Exit(1)
		}
	}
	// TODO deal with the rpc call's log
	_, _, hdrToCheck, err := observer.cli.GetTxsAndHeader(top, 0)
	if err != nil {
		log.Fatalf("[BtcObserver] failed to get header from full node when starting observer, so we just exit: %v", err)
		os.Exit(1)
	}
	if oldHash != hdrToCheck {
		dh := top
		for oldHash != hdrToCheck {
			top--
			oldHash, err = utils.GetHeaderHashFromPoly(observer.poly, top)
			if _, _, hdrToCheck, err = observer.cli.GetTxsAndHeader(top, 0); err != nil {
				top++
				log.Errorf("error: %v", err)
				utils.Wait(utils.SleepTime * time.Second)
				continue
			}
		}
		log.Warnf("[BtcObserver] orchain's best hash is not equal when height is %d, so we find common "+
			"ancestor %s:%d", dh, oldHash, top)
	}
	if top < btcCheckPoints[observer.NetParam.Name].Height {
		top = btcCheckPoints[observer.NetParam.Name].Height
	}
	if observer.conf.StartHeight != 0 {
		top = observer.conf.StartHeight
	}
	observer.initHdrsRelayed(hdrToCheck, top)
	log.Infof("[BtcObserver] get start from height %d, check once %d seconds", top, observer.conf.BtcObLoopWaitTime)
	tick := time.NewTicker(time.Duration(observer.conf.BtcObLoopWaitTime) * time.Second)
	for {
		select {
		case <-tick.C:
			newTop, newHash, err := observer.cli.GetCurrentHeightAndHash()
			if err != nil {
				log.Errorf("[BtcObserver] failed to get current height and hash and loop continue: %v", err)
				continue
			}
			if newTop == top && oldHash == newHash { // Prevent rollback
				continue
			}

		RETRY:
			if err = observer.cli.IsHeaderReady(newTop); err != nil {
				utils.Wait(1 * time.Second)
				goto RETRY
			}

			// check fork
			node := observer.hdrsRelayed.Back()
			for i := top; i+observer.conf.BtcObConfirmations >= top+1 && i <= top; i-- {
				_, _, hdrToCheck, err := observer.cli.GetTxsAndHeader(i, 0)
				if err != nil {
					log.Errorf("[BtcObserver] get header of height %d to check fork failed, loop continue: %v", i, err)
					i++
					continue
				}

				if hdrToCheck != node.Value.(Record).hash.String() {
					for j := top; j > i; j-- {
						observer.hdrsRelayed.Remove(observer.hdrsRelayed.Back())
					}
					for hdrToCheck != observer.hdrsRelayed.Back().Value.(Record).hash.String() {
						i--
						if _, _, hdrToCheck, err = observer.cli.GetTxsAndHeader(i, 0); err != nil {
							log.Errorf("[BtcObserver] get header of height %d from bitcoind failed and "+
								"loop continue: %v", i, err)
							i++
							continue
						}
						observer.hdrsRelayed.Remove(observer.hdrsRelayed.Back())
						if observer.hdrsRelayed.Len() == 0 {
							log.Fatal("[BtcObserver] for god's sake, a btc fork over 15 blocks!!!")
							os.Exit(1)
						}
					}
					top = i
					log.Warnf("[BtcObserver] fork happened at height %d and we start from here again", top+1)
					break
				}
				node = node.Prev()
			}

			h := top - observer.conf.BtcObConfirmations + 2
			if int64(h) < 0 {
				h = 0
			}
			noTxAfter := newTop - observer.conf.BtcObConfirmations + 1
			if newTop < observer.conf.BtcObConfirmations-1 {
				noTxAfter = 0
			}
			for ; h <= newTop; h++ {
				txns, header, hash, err := observer.cli.GetTxsAndHeader(h, noTxAfter)
				if err != nil {
					log.Errorf("[BtcObserver] failed to get header %s(%d), retry after 10 sec: %v", hash, h, err)
					h--
					utils.Wait(time.Second * utils.SleepTime)
					continue
				}
				if h > top {
					var buf bytes.Buffer
					_ = header.BtcEncode(&buf, wire.ProtocolVersion, wire.LatestEncoding)
					hash := header.BlockHash()
					hc <- &utils.Header{
						Raw:    buf.Bytes(),
						Height: h,
						Hash:   hash.String(),
					}
					observer.hdrsRelayed.PushBack(Record{
						hash:   hash,
						height: h,
					})
					if observer.hdrsRelayed.Len() > 15 {
						observer.hdrsRelayed.Remove(observer.hdrsRelayed.Front())
					}
				}
				if h <= noTxAfter && h != 0 {
					if count := observer.SearchTxInBlock(txns, h, cc); count > 0 {
						log.Infof("[BtcObserver] %d tx found in block(height:%d) %s", count, h, hash)
					}
				}
			}

			top = newTop
		}
	}
}

func (observer *BtcObserver) SearchTxInBlock(txns []*wire.MsgTx, height uint32, relaying chan *utils.CrossChainItem) int {
	count := 0
	for i := 0; i < len(txns); i++ {
		if !observer.checkIfCrossChainTx(txns[i]) {
			continue
		}
		var buf bytes.Buffer
		err := txns[i].BtcEncode(&buf, wire.ProtocolVersion, wire.LatestEncoding)
		if err != nil {
			log.Errorf("[SearchTxInBlock] failed to encode transaction: %v", err)
			continue
		}
		txid := txns[i].TxHash()
		proof, err := observer.cli.GetProof([]string{txid.String()})
		if err != nil {
			switch err.(type) {
			case utils.NetErr, utils.NeedToRetryErr:
				log.Errorf("[SearchTxInBlock] try to get proof for tx %s: %v", txid.String(), err)
				i--
				utils.Wait(time.Second * utils.SleepTime)
			default:
				log.Errorf("[SearchTxInBlock] failed to get proof for tx %s: %v", txid.String(), err)
			}
			continue
		}
		proofBytes, _ := hex.DecodeString(proof)
		relaying <- &utils.CrossChainItem{
			Proof:  proofBytes,
			Tx:     buf.Bytes(),
			Height: height,
			Txid:   txid,
		}
		log.Debugf("[SearchTxInBlock] eligible transaction found in block %d, txid: %s", height, txid.String())
		count++
	}
	return count
}

func (observer *BtcObserver) checkIfCrossChainTx(tx *wire.MsgTx) bool {
	if len(tx.TxOut) < 2 {
		return false
	}
	if tx.TxOut[0].Value <= 0 {
		return false
	}

	switch c1 := txscript.GetScriptClass(tx.TxOut[0].PkScript); c1 {
	case txscript.ScriptHashTy:
	case txscript.WitnessV0ScriptHashTy:
	default:
		return false
	}

	c2 := txscript.GetScriptClass(tx.TxOut[1].PkScript)
	if c2 != txscript.NullDataTy {
		return false
	}
	if len(tx.TxOut[1].PkScript) < 3 {
		return false
	}
	if tx.TxOut[1].PkScript[2] != btc.OP_RETURN_SCRIPT_FLAG {
		return false
	}

	return true
}

type PolyObConfig struct {
	PolyObLoopWaitTime int64  `json:"poly_ob_loop_wait_time"`
	WatchingKey        string `json:"watching_key"`
	PolyJsonRpcAddress string `json:"poly_json_rpc_address"`
	WalletFile         string `json:"wallet_file"`
	WalletPwd          string `json:"wallet_pwd"`
	NetType            string `json:"net_type"`
	WaitingCycle       uint32 `json:"waiting_cycle"`
}

type PolyObserver struct {
	poly    *sdk.PolySdk
	conf    *PolyObConfig
	retryDB *db.RetryDB
}

func NewPolyObserver(poly *sdk.PolySdk, conf *PolyObConfig, rdb *db.RetryDB) *PolyObserver {
	return &PolyObserver{
		poly:    poly,
		conf:    conf,
		retryDB: rdb,
	}
}

func (observer *PolyObserver) Listen(collecting chan *utils.FromPolyItem) {
	top, err := observer.poly.GetCurrentBlockHeight()
	if err != nil {
		log.Fatalf("[PolyObserver] failed to get current height from orchain", err)
		os.Exit(1)
	}
	if maybe := observer.retryDB.GetPolyHeight(); maybe != 0 {
		top = maybe
	}
	if top < polyCheckPoints[observer.conf.NetType].Height {
		top = polyCheckPoints[observer.conf.NetType].Height
	}
	lastRecorded := top
	log.Infof("[PolyObserver] get start from height %d, check once %d seconds", top, observer.conf.PolyObLoopWaitTime)
	tick := time.NewTicker(time.Duration(observer.conf.PolyObLoopWaitTime) * time.Second)
	for {
		select {
		case <-tick.C:
			count := 0
			newTop, err := observer.poly.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("[PolyObserver] failed to get current height, retry after %d sec: %v",
					observer.conf.PolyObLoopWaitTime, err)
				continue
			}
			if newTop-top == 0 {
				continue
			}
			log.Tracef("[PolyObserver] observing from height %d to height %d", top, newTop)

			h := top + 1
			for h <= newTop {
				events, err := observer.poly.GetSmartContractEventByBlock(h)
				if err != nil {
					log.Errorf("[PolyObserver] GetSmartContractEventByBlock failed, retry after 10 sec: %v", err)
					utils.Wait(time.Second * utils.SleepTime)
					continue
				}

				for _, e := range events {
					for _, n := range e.Notify {
						states, ok := n.States.([]interface{})
						if !ok {
							continue
						}
						name, ok := states[0].(string)
						if ok && name == observer.conf.WatchingKey {
							from := int64(states[1].(float64))
							tx := states[3].(string)
							collecting <- &utils.FromPolyItem{
								Tx: tx,
							}
							count++
							log.Debugf("[PolyObserver] captured from chain-id %d: %s when height is %d", from,
								tx, h)
						}
					}
				}

				h++
			}
			if count > 0 {
				log.Infof("[PolyObserver] total %d transactions captured this time", count)
			}
			top = newTop
			if count > 0 || top-lastRecorded >= observer.conf.WaitingCycle {
				err := observer.retryDB.SetBtcHeight(top)
				log.Tracef("[PolyObserver] write poly height %d", top)
				if err != nil {
					log.Errorf("[PolyObserver] failed to set poly height: %v", err)
					continue
				}
				lastRecorded = top
			}
		}
	}
}

type Record struct {
	hash   chainhash.Hash
	height uint32
}

func (r *Record) String() string {
	return r.hash.String() + ":" + strconv.FormatInt(int64(r.height), 10)
}
