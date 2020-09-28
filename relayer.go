package btc_relayer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/evdatsion/btc-relayer-poly/db"
	"github.com/evdatsion/btc-relayer-poly/log"
	"github.com/evdatsion/btc-relayer-poly/observer"
	ru "github.com/evdatsion/btc-relayer-poly/utils"
)

type BtcRelayer struct {
	btcOb       *observer.BtcObserver
	polyOb      *observer.PolyObserver
	account     *sdk.Account
	cciChan     chan *ru.CrossChainItem
	headersChan chan *ru.Header
	collecting  chan *ru.FromPolyItem
	poly        *sdk.PolySdk
	config      *RelayerConfig
	cli         *ru.RestCli
	retryDB     *db.RetryDB
}

func NewBtcRelayer(conf *RelayerConfig, pwd []byte) (*BtcRelayer, error) {
	poly := sdk.NewPolySdk()
	if err := ru.SetUpPoly(poly, conf.PolyObConf.PolyJsonRpcAddress); err != nil {
		return nil, fmt.Errorf("failed to set up poly: %v", err)
	}
	poly.NewRpcClient().SetAddress(conf.PolyObConf.PolyJsonRpcAddress)
	acct, err := GetAccountByPassword(poly, conf.PolyObConf.WalletFile, pwd)
	if err != nil {
		return nil, fmt.Errorf("GetAccountByPassword failed: %v", err)
	}

	if !checkIfExist(conf.RetryDBPath) {
		os.Mkdir(conf.RetryDBPath, os.ModePerm)
	}
	rdb, err := db.NewRetryDB(conf.RetryDBPath, conf.RetryTimes, conf.RetryDuration, conf.MaxReadSize)
	if err != nil {
		return nil, fmt.Errorf("failed to new retry db: %v", err)
	}

	store, err := poly.GetStorage(utils.SideChainManagerContractAddress.ToHexString(),
		append([]byte(side_chain_manager.SIDE_CHAIN), utils.GetUint64Bytes(ru.BTC_ID)...))
	if err != nil {
		return nil, fmt.Errorf("failed to get blksToWait from chain: %v", err)
	}
	if store == nil {
		return nil, errors.New("blkToWait which get from chain is nil")
	}
	sideChain := new(side_chain_manager.SideChain)
	err = sideChain.Deserialization(common.NewZeroCopySource(store))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize side chain: %v", err)
	}
	conf.BtcObConf.BtcObConfirmations = uint32(sideChain.BlocksToWait)

	cli := ru.NewRestCli(conf.BtcObConf.BtcJsonRpcAddress, conf.BtcObConf.User, conf.BtcObConf.Pwd)
	return &BtcRelayer{
		btcOb:       observer.NewBtcObserver(conf.BtcObConf, cli, poly),
		polyOb:      observer.NewPolyObserver(poly, conf.PolyObConf, rdb),
		account:     acct,
		cciChan:     make(chan *ru.CrossChainItem, 100),
		headersChan: make(chan *ru.Header, 10),
		collecting:  make(chan *ru.FromPolyItem, 100),
		poly:        poly,
		config:      conf,
		cli:         cli,
		retryDB:     rdb,
	}, nil
}

func (relayer *BtcRelayer) BtcListen() {
	relayer.btcOb.Listen(relayer.cciChan, relayer.headersChan)
}

func (relayer *BtcRelayer) PolyListen() {
	relayer.polyOb.Listen(relayer.collecting)
}

func (relayer *BtcRelayer) ReBroadcast() {
	log.Info("[ReBroadcast] rebroadcasting")
	tick := time.NewTicker(time.Duration(relayer.config.RetryDuration) * time.Minute)
	for {
		select {
		case <-tick.C:
			txArr, err := relayer.retryDB.GetAll()
			if err != nil {
				log.Debugf("[BtcRelayer] failed to get retry tx: %v", err)
				continue
			}
			for i := 0; i < len(txArr); i++ {
				txb, _ := hex.DecodeString(txArr[i])
				mtx := wire.NewMsgTx(wire.TxVersion)
				mtx.BtcDecode(bytes.NewBuffer(txb), wire.ProtocolVersion, wire.LatestEncoding)
				txid, err := relayer.cli.BroadcastTx(txArr[i])
				if err != nil {
					switch err.(type) {
					case ru.NeedToRetryErr:
						log.Errorf("[BtcRelayer] rebroadcast %s failed: %v", mtx.TxHash().String(), err)
					case ru.NetErr:
						i--
						log.Errorf("[BtcRelayer] net err happened, rebroadcast %s failed: %v", mtx.TxHash().String(), err)
						ru.Wait(time.Second * ru.SleepTime)
					default:
						log.Infof("[BtcRelayer] no need to rebroadcast and delete this tx %s...%s: %v", txArr[i][:16],
							txArr[i][len(txArr[i])-16:], err)
						err = relayer.retryDB.Del(txArr[i])
						if err != nil {
							log.Errorf("[BtcRelayer] failed to delete tx %s(%s): %v", txid, txArr[i], err)
						}
					}
				} else {
					log.Infof("[BtcRelayer] rebroadcast and delete tx: %s", txid)
					err = relayer.retryDB.Del(txArr[i])
					if err != nil {
						log.Errorf("[BtcRelayer] failed to delete tx %s(%s): %v", txid, txArr[i], err)
					}
				}
			}
		}
	}
}

func (relayer *BtcRelayer) Broadcast() {
	log.Infof("[Broadcast] start broadcasting")
	for item := range relayer.collecting {
		txid, err := relayer.cli.BroadcastTx(item.Tx)
		if err != nil {
			switch err.(type) {
			case ru.NeedToRetryErr:
				log.Infof("[BtcRelayer] need to rebroadcast this tx %s...%s: %v", item.Tx[:16], item.Tx[len(item.Tx)-16:], err)
				err = relayer.retryDB.Put(item.Tx)
				if err != nil {
					log.Errorf("[BtcRelayer] failed to put tx in db: %v", err)
				}
			case ru.NetErr:
				relayer.collecting <- item
				log.Errorf("[BtcRelayer] net err happened, put it(%s...%s) back to channel: %v", item.Tx[:16],
					item.Tx[len(item.Tx)-16:], err)
				ru.Wait(time.Second * ru.SleepTime)
			default:
				log.Errorf("[BtcRelayer] failed to broadcast tx: %v", err)
			}
			continue
		}
		log.Infof("[BtcRelayer] broadcast tx: %s", txid)
	}
}

func (relayer *BtcRelayer) SendCCIFromDB() {
	log.Info("[SendCCIFromDB] starting sending tx need to resend from db")
	tick := time.NewTicker(time.Second * time.Duration(relayer.config.RetryCCIDura))
	for {
		select {
		case <-tick.C:
			curr, _, err := ru.GetCurrHeightFromPoly(relayer.poly)
			if err != nil {
				relayer.handleErr(err, nil)
				continue
			}
			arr, err := relayer.retryDB.GetCCIUnderHeightAndDel(curr - relayer.config.BtcObConf.BtcObConfirmations + 1)
			if err != nil {
				log.Errorf("[SendCCIFromDB] failed to GetCCIUnderHeightAndDel: %v", err)
				continue
			} else if arr == nil || len(arr) == 0 {
				continue
			}
			for _, v := range arr {
				log.Debugf("[SendCCIFromDB] send (txid: %s, height: %d) to channel", v.Txid.String(), v.Height)
				relayer.cciChan <- v
			}
		}
	}
}

func (relayer *BtcRelayer) RelayTx() {
	log.Info("[RelayTx] start relaying tx")
	for item := range relayer.cciChan {
		besth, _, err := ru.GetCurrHeightFromPoly(relayer.poly)
		if err != nil {
			relayer.handleErr(err, item)
			continue
		}
		if besth < relayer.config.BtcObConf.BtcObConfirmations-1+item.Height {
			_ = relayer.retryDB.PutCCI(item)
			log.Infof("[RelayTx] put a tx into db: txid: %s, height: %d", item.Txid, item.Height)
			continue
		}

	RETRY:
		txHash, err := relayer.poly.Native.Ccm.ImportOuterTransfer(ru.BTC_ID, item.Tx, uint32(item.Height),
			item.Proof, relayer.account.Address[:], []byte{}, relayer.account)
		if err != nil {
			relayer.handleErr(err, item)
			continue
		}

		tick := time.NewTicker(time.Millisecond)
		startTime := time.Now()
		for range tick.C {
			tx, _ := relayer.poly.GetTransaction(txHash.ToHexString())
			if tx != nil && len(tx.Raw) != 0 {
				break
			}
			if time.Now().Sub(startTime).Seconds() > relayer.config.TxTimeOut {
				log.Warnf("[RelayHeaders] poly tx %s has been sent but not found on chain for %.1f sec",
					txHash.ToHexString(), relayer.config.TxTimeOut)
				goto RETRY
			}
		}

		log.Infof("[RelayTx] tx %s sent to poly: txid: %s, height: %d", txHash.ToHexString(),
			item.Txid, item.Height)
	}
}

func (relayer *BtcRelayer) relayHdrsBatchly(hdrs ru.Headers) {
	rawHdrs := hdrs.GetSortedRawHeaders()
	for i := 0; i < len(rawHdrs); i += ru.HDR_LIMIT_PER_BATCH {
		var batch [][]byte
		if i+ru.HDR_LIMIT_PER_BATCH > len(rawHdrs) {
			batch = rawHdrs[i:]
		} else {
			batch = rawHdrs[i : i+ru.HDR_LIMIT_PER_BATCH]
		}
		hdrsToShow := hdrs[i : i+len(batch)]
	RETRY:
		txHash, err := relayer.poly.Native.Hs.SyncBlockHeader(ru.BTC_ID, relayer.account.Address,
			batch, relayer.account)
		if err != nil {
			if strings.Contains(err.Error(), "orphan") {
				log.Warnf("[RelayHeaders] headers committed %s has been treated as an orphan, "+
					"so we continue: %v", getLogHeadersContent(hdrsToShow, ""), err)
				ru.Wait(time.Second * ru.SleepTime)
				goto RETRY
			}
			switch err.(type) {
			case client.PostErr:
				log.Infof("[RelayHeaders] receive post err, so we wait for %s and retry: %v",
					ru.SleepTime, err)
				ru.Wait(time.Second * ru.SleepTime)
				goto RETRY
			default:
				log.Fatalf("[RelayHeaders] invokeNativeContract error: %v", err)
				panic(err)
			}
		}

		tick := time.NewTicker(time.Millisecond)
		startTime := time.Now()
		for range tick.C {
			tx, _ := relayer.poly.GetTransaction(txHash.ToHexString())
			if tx != nil && len(tx.Raw) != 0 {
				break
			}
			if time.Now().Sub(startTime).Seconds() > relayer.config.TxTimeOut {
				log.Warnf("[RelayHeaders] poly tx %s has been sent but not found on chain for %.1f sec",
					txHash.ToHexString(), relayer.config.TxTimeOut)
				goto RETRY
			}
		}
		log.Tracef(getLogHeadersContent(hdrsToShow, txHash.ToHexString()))
	}
}

func (relayer *BtcRelayer) RelayHeaders() {
	log.Info("[RelayHeaders] start relaying headers")
	hdrs := ru.Headers(make([]*ru.Header, 0))
	tick := time.NewTicker(time.Second * time.Duration(relayer.config.SendHeadersDura))

	for {
		select {
		case h := <-relayer.headersChan:
			log.Debugf("[RelayHeaders] receive a header: hash %s, height %d", h.Hash, h.Height)
			hdrs = append(hdrs, h)
			relayer.relayHdrsBatchly(hdrs)

		case <-tick.C:
			if hdrs.Len() > 0 {
				relayer.relayHdrsBatchly(hdrs)
			}
		}
		hdrs = ru.Headers(make([]*ru.Header, 0))
	}
}

func (relayer *BtcRelayer) handleErr(err error, item *ru.CrossChainItem) {
	switch err.(type) {
	case client.PostErr:
		log.Errorf("[BtcRelayer] failed to relay and post err: %v", err)
		if item != nil {
			go func() {
				relayer.cciChan <- item
			}()
		}
		ru.Wait(time.Second * ru.SleepTime)
	default:
		log.Errorf("[BtcRelayer] invokeNativeContract error: %v", err)
	}
}

type RelayerConfig struct {
	BtcObConf       *observer.BtcObConfig  `json:"btc_ob_conf"`
	PolyObConf      *observer.PolyObConfig `json:"poly_ob_conf"`
	RetryDuration   int                    `json:"retry_duration"`
	RetryTimes      int                    `json:"retry_times"`
	RetryDBPath     string                 `json:"retry_db_path"`
	LogLevel        int                    `json:"log_level"`
	SleepTime       int                    `json:"sleep_time"`
	MaxReadSize     uint64                 `json:"max_read_size"`
	RetryCCIDura    int                    `json:"retry_cci_dura"`
	SendHeadersDura int                    `json:"send_headers_dura"`
	TxTimeOut       float64                `json:"tx_time_out"`
}

func NewRelayerConfig(file string) (*RelayerConfig, error) {
	conf := &RelayerConfig{}
	err := conf.Init(file)
	if err != nil {
		return conf, fmt.Errorf("[NewRelayerConfig] failed to new config: %v", err)
	}
	return conf, nil
}

func (this *RelayerConfig) Init(fileName string) error {
	err := this.loadConfig(fileName)
	if err != nil {
		return fmt.Errorf("loadConfig error:%s", err)
	}
	return nil
}

func (this *RelayerConfig) loadConfig(fileName string) error {
	data, err := this.readFile(fileName)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, this)
	if err != nil {
		return fmt.Errorf("json.Unmarshal TestConfig:%s error:%s", data, err)
	}
	return nil
}

func (this *RelayerConfig) readFile(fileName string) ([]byte, error) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("OpenFile %s error %s", fileName, err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			fmt.Println(fmt.Errorf("file %s close error %s", fileName, err))
		}
	}()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll %s error %s", fileName, err)
	}
	return data, nil
}

func GetAccountByPassword(sdk *sdk.PolySdk, path string, pwd []byte) (*sdk.Account, error) {
	wallet, err := sdk.OpenWallet(path)
	if err != nil {
		return nil, fmt.Errorf("open wallet error: %v", err)
	}
	user, err := wallet.GetDefaultAccount(pwd)
	if err != nil {
		return nil, fmt.Errorf("getDefaultAccount error: %v", err)
	}
	return user, nil
}

func checkIfExist(dir string) bool {
	_, err := os.Stat(dir)
	if err != nil && !os.IsExist(err) {
		return false
	}
	return true
}

func getLogHeadersContent(hdrs ru.Headers, txHash string) (content string) {
	content = "headers: ["
	for _, v := range hdrs {
		content += fmt.Sprintf("%d:%s, ", v.Height, v.Hash)
	}
	if txHash == "" {
		content += "] "
		return
	}
	content += fmt.Sprintf("] txhash: %s", txHash)
	return
}
