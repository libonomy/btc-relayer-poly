package btc_relayer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/evdatsion/btc-relayer-poly/log"
	"github.com/evdatsion/btc-relayer-poly/observer"
	"github.com/evdatsion/btc-relayer-poly/utils"
	"github.com/stretchr/testify/assert"
)

var (
	txArr = []string{
		"01000000019f074c07f34ffdcac88f76aa403e0725a90870b974c777a7236d6db067481ff2020000006b483045022100c5647452812dd245de91536de723d35239cbd49bb4dd924a5b6376b099a8a716022078938060af6771a44913893eaf0b091de365ee3a7a6ecefa830bf5d4caf6c996012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a4a8ae0800000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
		"01000000014d369f59ba828a4996f47b03229cbb976a0d0ed841c8c2f7a8e843289b15e631020000006a47304402202676093014919f3aa5dd5237566e4690dfc3503809246c3601cac38c4bd7636202207277e47ec95a28cf6eb30bceb36252704086e2b04c13e35797b0862741d44528012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a4d8230900000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
		"01000000012de9998067a46027dff12f8c114cb67f9788f52af731caa22a4c0b68babc58d0020000006a4730440220014f7b9c643ce47275552583fe3785f1d72307207b9e95ec293b16cbb15e10bc02205b6452982da43ebc2ddba531cba43a88baad003f2fcaef265e4ec30e8c077b0a012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a4e84a0900000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
		"0100000001e94f4feea73d3a44ad41cc52ea9ba5ccba9094dbd351310497eafff8233e2bec020000006b483045022100b1d0ec22de2404bf25d620e2c4488d2489d0eb46beca29f5dc219ee464ecd9e3022068a3f0c045b86e14fb99c72173ff9dd8d65dd784fc3af2050085a7c8e9b67cdb012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a418c00900000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
		"0100000001cbf0d729953a6227098a45752ed871c621f938260a53bfc6c998a347e2fd62e4020000006b483045022100f2e9590d6a9fcd5abce3775b0d263194547890f825350e81927468d807c43dd70220165a5edbca9f1cd42a6197a20ac4d97985dcde02f303b061541c1f86e026c398012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a430390a00000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
		"01000000017b60622809f978db6b95b09cec9789e2d68539b5eb7b2015ae2f7d79028b320c020000006b48304502210088a67aa604db724f34b2410e813927d26ad3489655cfb252934b25713890a17b02203bbe698595467da469fd20a09049c5920e8f70cae591605375d16bc801253c1f012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a430390a00000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
		"010000000140b1e5b05e26757f799ebf9f9018f970e77b0e6f7123d19fabaf373a32c3d0a0020000006a47304402204fb2d2d3edebd65675aa8b27f24d2b2398cec0fbf9cac2cfcb7def6df9b7cd6202205d6881aae4b4d65d63efbc1ed1cbb669dc493811b94f2c1629573a5ef5568706012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03204e00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d3870000000000000000276a256600000000000000020000000000000000f3b8a17f1f957f60c88f105e32ebff3f022e56a430390a00000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000",
	}
)

func TestNewRelayerConfig(t *testing.T) {
	_, err := NewRelayerConfig("./conf.json")
	assert.NoError(t, err)
}

func TestNewBtcRelayer(t *testing.T) {
	conf, _ := NewRelayerConfig("./conf.json")
	_, err := NewBtcRelayer(conf, []byte("1"))
	assert.NoError(t, err)
}

func getRelayer() (*BtcRelayer, error) {
	conf := RelayerConfig{
		PolyObConf: &observer.PolyObConfig{
			WaitingCycle:       100,
			WatchingKey:        "btcTxToRelay",
			WalletPwd:          "1",
			PolyObLoopWaitTime: 2,
			NetType:            "test",
			WalletFile:         "./wallet.dat",
			PolyJsonRpcAddress: startMockPolyServer(),
		},
		BtcObConf: &observer.BtcObConfig{
			NetType:           "regtest",
			BtcJsonRpcAddress: startMockBtcServer(),
		},
		SendHeadersDura: 2,
		SleepTime:       2,
		RetryCCIDura:    2,
		MaxReadSize:     500,
		LogLevel:        0,
		RetryDBPath:     "./",
		RetryDuration:   1,
		RetryTimes:      5,
	}
	log.InitLog(conf.LogLevel, os.Stdout)

	return NewBtcRelayer(&conf, []byte("1"))
}

func TestBtcRelayer_RelayHeaders(t *testing.T) {
	defer os.RemoveAll("./retry.bin")

	r, err := getRelayer()
	assert.NoError(t, err)

	go func() {
		raw, _ := hex.DecodeString("0000002050c2f32c30615106cc58b01352a13e6f309d7e6f142ccbe58d37a709f81a3f4739825ad49375ac5ff5fc292df9ed518124035f4edcf9b48d0aaf49b29ef7770ef410415effff7f2000000000")
		tick := time.NewTicker(time.Second)
		for _ = range tick.C {
			r.headersChan <- &utils.Header{
				Hash:   "257e0ef983e245d26972b4effc959e8c5e819322d73dfce347fc7baf3c845a91",
				Height: 1804,
				Raw:    raw,
			}
		}
	}()
	go r.RelayHeaders()

	time.Sleep(10 * time.Second)
}

func TestBtcRelayer_RelayTx(t *testing.T) {
	defer os.RemoveAll("./retry.bin")

	r, err := getRelayer()
	assert.NoError(t, err)

	go func() {
		tick := time.NewTicker(time.Second)
		for _ = range tick.C {
			r.cciChan <- &utils.CrossChainItem{
				Height: 1804,
			}
		}
	}()
	go r.RelayTx()

	time.Sleep(10 * time.Second)
}

func TestBtcRelayer_ReBroadcast(t *testing.T) {
	defer os.RemoveAll("./retry.bin")

	r, err := getRelayer()
	if err != nil {
		t.Fatal(err)
	}
	log.InitLog(0, log.Stdout)
	for _, tx := range txArr[:3] {
		r.retryDB.Put(tx)
	}

	go r.ReBroadcast()
	time.Sleep(2 * time.Minute)
}

func TestBtcRelayer_Broadcast(t *testing.T) {
	defer os.RemoveAll("./retry.bin")

	r, err := getRelayer()
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range txArr[:3] {
		r.collecting <- &utils.FromPolyItem{
			Tx: v,
		}
	}
	go r.Broadcast()

	time.Sleep(10 * time.Second)
}

func GetCCI() (utils.CrossChainItem, int) {
	txid, _ := chainhash.NewHashFromStr("fd285cf687d0759f215e63b3234e1e2a010cb8060d2b4775793ec4447b8385c1")
	proof, _ := hex.DecodeString("01000030c64cb1478e2a2a1774a55ea35b272a397730422ec3e47244f9eb0a062d5a3f1c88a8701698569f51645ff81ae2a8f45c1dbcf369aa9e1f8600f02b20d2c8a156dfb30e5effff7f2000000000080000000490eb94f4609ad4d50547ea65730da8d276777a2c90056f9978a5a2df47eabb6c1786f80a919e1531433f0be9469987602193c5abe5ffa9520dc0942958e6c521c185837b44c43e7975472b0d06b80c012a1e4e23b3635e219f75d087f65c28fd51634411a436e65609dce1f0eb21da7109f01ab468927f81270e90684499b9a7012b")
	rawTx, _ := hex.DecodeString("0100000001633f586f140397287ee87b41c1feb4aad5447bbdc66bc4a11f3a400a637ec0e3020000006b483045022100c67f2ad9b598134c9554490bc411349a122529e9b052ee2673d4326021c69cfb02205f8f63ccab64de8244fecc8727afa38869fddda10770f0cff62227cc10e212da012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff039d8f00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d38700000000000000003d6a3b660200000000000000000000000000000014dc68bcc275bf668129c6d214202f6d6ee77e309214f3b8a17f1f957f60c88f105e32ebff3f022e56a45a37052a010000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000")
	return utils.CrossChainItem{
		Height: 1803,
		Txid:   *txid,
		Proof:  proof,
		Tx:     rawTx,
	}, 36 + 8 + len(proof) + len(rawTx)
}

func TestBtcRelayer_SendCCIFromDB(t *testing.T) {
	defer os.RemoveAll("./retry.bin")

	hb, _ := hex.DecodeString("0000002013db9df97dfc62dff7035b6ab5d2f35aeca48f3df4993e0e6d000000000000001d9bd5e8cfca3b935cc01ee21dfce7aa1b358ae3326d4cf419da7b492b3a4a4d5f670f5eef28021a06668403")
	h := new(utils.Header)
	h.Height = 100
	h.Hash = "000000000000000bf629cdff897dbe0f3128aef5e378b0bc093016fd9c15aa27"
	h.Raw = hb

	r, _ := getRelayer()

	items := make([]utils.CrossChainItem, 6)
	items[0], _ = GetCCI()
	items[1], _ = GetCCI()

	items[2], _ = GetCCI()
	items[2].Height = 1804
	items[3], _ = GetCCI()
	items[3].Height = 1804
	items[4], _ = GetCCI()
	items[4].Height = 1804

	items[5], _ = GetCCI()
	items[5].Height = 1805

	for i, v := range items {
		v.Tx[0] = byte(i)
		_ = r.retryDB.PutCCI(&v)
	}
	go r.SendCCIFromDB()

	time.Sleep(time.Second * 10)
	arr, _ := r.retryDB.GetCCIUnderHeightAndDel(1805)
	assert.Equal(t, 1, len(arr))
}

func startMockBtcServer() string {
	ms := httptest.NewServer(http.HandlerFunc(handleReq))
	return ms.URL
}

func handleReq(w http.ResponseWriter, r *http.Request) {
	rb, _ := ioutil.ReadAll(r.Body)
	req := new(utils.Request)
	_ = json.Unmarshal(rb, req)

	switch req.Method {
	case "sendrawtransaction":
		res, _ := btcjson.MarshalResponse(1, "", nil)
		w.Write(res)
	default:
		fmt.Fprint(w, "wrong method")
	}
}

func startMockPolyServer() string {
	ms := httptest.NewServer(http.HandlerFunc(handlePolyReq))
	return ms.URL
}

func handlePolyReq(w http.ResponseWriter, r *http.Request) {
	rb, _ := ioutil.ReadAll(r.Body)
	req := new(client.JsonRpcRequest)
	_ = json.Unmarshal(rb, req)

	switch req.Method {
	case client.RPC_GET_STORAGE:
		if req.Params[1].(string) ==
			hex.EncodeToString(append([]byte(side_chain_manager.SIDE_CHAIN), utils2.GetUint64Bytes(utils.BTC_ID)...)) {
			sc := &side_chain_manager.SideChain{
				Router:       0,
				BlocksToWait: 1,
				ChainId:      1,
				Name:         "BTC",
			}
			sink := common3.NewZeroCopySink(nil)
			_ = sc.Serialization(sink)
			resp := map[string]interface{}{
				"error":  int64(0),
				"desc":   "SUCCESS",
				"result": common3.ToHexString(sink.Bytes()),
			}
			rb, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"error":   resp["error"],
				"desc":    resp["desc"],
				"result":  resp["result"],
				"id":      req.Id,
			})

			w.Write(rb)
		} else if req.Params[1].(string) ==
			hex.EncodeToString(append([]byte(common.CURRENT_HEADER_HEIGHT), utils2.GetUint64Bytes(utils.BTC_ID)...)) {
			rawBh, _ := hex.DecodeString("0000002050c2f32c30615106cc58b01352a13e6f309d7e6f142ccbe58d37a709f81a3f4739825ad49375ac5ff5fc292df9ed518124035f4edcf9b48d0aaf49b29ef7770ef410415effff7f2000000000")
			bh := new(wire.BlockHeader)
			_ = bh.BtcDecode(bytes.NewBuffer(rawBh), wire.ProtocolVersion, wire.LatestEncoding)

			sh := &MockStoredHeader{}
			sh.Header = *bh
			sh.Height = 1804
			sh.totalWork = big.NewInt(0)

			sink := new(common3.ZeroCopySink)
			sh.Serialization(sink)

			resp := map[string]interface{}{
				"error":  int64(0),
				"desc":   "SUCCESS",
				"result": common3.ToHexString(sink.Bytes()),
			}
			rb, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"error":   resp["error"],
				"desc":    resp["desc"],
				"result":  resp["result"],
				"id":      req.Id,
			})
			w.Write(rb)
		}
	case client.RPC_SEND_TRANSACTION:
		resp := map[string]interface{}{
			"error":  int64(0),
			"desc":   "SUCCESS",
			"result": "ea9822ea747b14af52e2eb7986d8e145960f0bfb2c0df1ce00d98fd5061e5dbc",
		}
		rb, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"error":   resp["error"],
			"desc":    resp["desc"],
			"result":  resp["result"],
			"id":      req.Id,
		})

		w.Write(rb)
	default:
		fmt.Fprint(w, "wrong method")
	}
}

type MockStoredHeader struct {
	Header    wire.BlockHeader
	Height    uint32
	totalWork *big.Int
}

func (this *MockStoredHeader) Serialization(sink *common3.ZeroCopySink) {
	buf := bytes.NewBuffer(nil)
	this.Header.Serialize(buf)
	sink.WriteVarBytes(buf.Bytes())
	sink.WriteUint32(this.Height)
	biBytes := this.totalWork.Bytes()
	pad := make([]byte, 32-len(biBytes))
	//serializedBI := append(pad, biBytes...)
	sink.WriteVarBytes(append(pad, biBytes...))
}

func TestNewBtcObserver(t *testing.T) {
	conf, err := NewRelayerConfig("./conf.json")
	if err != nil {
		t.Fatal(err)
	}

	poly := poly_go_sdk.NewPolySdk()
	poly.NewRpcClient().SetAddress(conf.PolyObConf.PolyJsonRpcAddress)

	//fmt.Println(utils.GetCurrHeightFromPoly(poly))

	raw, err := poly.GetStorage(utils2.HeaderSyncContractAddress.ToHexString(),
		append([]byte(common.CURRENT_HEADER_HEIGHT), utils2.GetUint64Bytes(3)...))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(utils2.GetBytesUint32(raw))
}
