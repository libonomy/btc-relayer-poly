package observer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/evdatsion/btc-relayer-poly"
	db2 "github.com/evdatsion/btc-relayer-poly/db"
	"github.com/evdatsion/btc-relayer-poly/utils"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const (
	USER = "test"
	PWD  = "test"

	BLOCK1804 = "0000002050c2f32c30615106cc58b01352a13e6f309d7e6f142ccbe58d37a709f81a3f4739825ad49375ac5ff5fc292df9ed518124035f4edcf9b48d0aaf49b29ef7770ef410415effff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff05020c070101ffffffff0247a41200000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac0000000000000000266a24aa21a9edb360526d4ae9ec8a8692f7a945f9f25c61d95317befc5a4d9b2741770ade8587012000000000000000000000000000000000000000000000000000000000000000000000000001000000011e108cea6d59ded46f1776b1d1cb4a7d68d715e1e1f1179814e8055046ac7280020000006a47304402202cc084dcfffcc2d447d0d8898c2cb84388c23d50d600e7800507bc2f50b4a9ef022034d149caf0f69486707fdf20fe8cc2c002741cb2fd4a58c20f64155b72757a35012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff03009435770000000022002044978a77e4e983136bf1cca277c45e5bd4eff6a7848e900416daf86fd32c274300000000000000003d6a3b660300000000000000000000000000000014ff4b747b7eff58c01d87f79958901a2024ec7aa514f3b8a17f1f957f60c88f105e32ebff3f022e56a400cdbbb2000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000"
	BLOCK1805 = "00000020915a843caf7bfc47e3fc3dd72293815e8c9e95fcefb47269d245e283f90e7e25062e6b40a9be5a5c1590dcff3d9e0a7cb80df890227a9b6c3989ebb00ef840051b11415effff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff05020d070101ffffffff0247a41200000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac0000000000000000266a24aa21a9ed4c50c4184e3b1489cbeb407e0c1a8964eba8e7776f8ef55c58a3b51c0b2b1c6b012000000000000000000000000000000000000000000000000000000000000000000000000001000000016fda20136e3b7b755f57b357fa133023ab8cc748c4ff326cf06bc7080b9e9db6020000006a47304402207e11632f961e9cccb65a08d178b1712254a7d9ababe4a64ed290f58525850d2e0220282bea8dcfb47bbbe6125f5362b82c872388e93484392ded93208fa25440cc15012103128a2c4525179e47f38cf3fefca37a61548ca4610255b3fb4ee86de2d3e80c0fffffffff0300ca9a3b0000000022002044978a77e4e983136bf1cca277c45e5bd4eff6a7848e900416daf86fd32c274300000000000000003d6a3b660300000000000000000000000000000014ff4b747b7eff58c01d87f79958901a2024ec7aa514f3b8a17f1f957f60c88f105e32ebff3f022e56a4deb753ee000000001976a91428d2e8cee08857f569e5a1b147c5d5e87339e08188ac00000000"
)

func TestBtcObserver_SearchTxInBlock(t *testing.T) {
	cli := utils.NewRestCli(startMockBtcServer(), USER, PWD)
	line := make(chan *utils.CrossChainItem, 2)
	o := NewBtcObserver(&BtcObConfig{
		Pwd:     PWD,
		NetType: "test",
		User:    USER,
	}, cli, nil)
	blk, err := o.cli.GetTxsInBlock("257e0ef983e245d26972b4effc959e8c5e819322d73dfce347fc7baf3c845a91")
	assert.NoError(t, err)
	go func() {
		for {
			select {
			case <-line:
			}
		}
	}()
	count := o.SearchTxInBlock(blk.Transactions, 1804, line)
	assert.Equal(t, 1, count)
}

func TestBtcObserver_Listen(t *testing.T) {
	poly := poly_go_sdk.NewPolySdk()
	poly.NewRpcClient().SetAddress(startMockPolyServer())
	cli := utils.NewRestCli(startMockBtcServer(), USER, PWD)

	line := make(chan *utils.CrossChainItem, 10)
	headers := make(chan *utils.Header, 10)

	o := NewBtcObserver(&BtcObConfig{
		NetType:            "regtest",
		BtcObConfirmations: 1,
		BtcObLoopWaitTime:  2,
	}, cli, poly)
	go o.Listen(line, headers)

	txid := make([]string, 0)
	go func() {
		for item := range line {
			txid = append(txid, item.Txid.String())
		}
	}()

	hdrs := make([]string, 0)
	go func() {
		for h := range headers {
			hdrs = append(hdrs, h.Hash)
		}
	}()

	time.Sleep(time.Second * 10)
	assert.Equal(t, 1, len(txid))
	assert.Equal(t, "8dcf5fee81c6320f9f8ea983138874e968a6991cd571337166771c0500a03022", txid[0])
	assert.Equal(t, 1, len(hdrs))
	assert.Equal(t, "32297a88e4f3bef3bcbdd22a2eef19b4671c4f3205f9483ba6e6def114ba6907", hdrs[0])
}

func TestPolyObserver_Listen(t *testing.T) {
	db, _ := db2.NewRetryDB("./", 5, 1, 500)
	defer os.RemoveAll("./retry.bin")

	poly := poly_go_sdk.NewPolySdk()
	poly.NewRpcClient().SetAddress(startMockPolyServer())

	aconf := &PolyObConfig{}
	aconf.WalletFile = "../wallet.dat"
	aconf.NetType = "regtest"
	aconf.PolyObLoopWaitTime = 2
	aconf.WalletPwd = "1"
	aconf.WatchingKey = "btcTxToRelay"
	aconf.WaitingCycle = 100

	c := make(chan *utils.FromPolyItem)

	aob := NewPolyObserver(poly, aconf, db)
	go aob.Listen(c)

	tx := make([]string, 0)
	go func() {
		for item := range c {
			tx = append(tx, item.Tx)
		}
	}()

	time.Sleep(10 * time.Second)

	assert.Equal(t, 1, len(tx))
	assert.Equal(t, "tx", tx[0])
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
	case "gettxoutproof":
		res, _ := btcjson.MarshalResponse(1, "proof", nil)
		w.Write(res)
	case "getblock":
		var res []byte
		if req.Params[0].(string) == "257e0ef983e245d26972b4effc959e8c5e819322d73dfce347fc7baf3c845a91" {
			res, _ = btcjson.MarshalResponse(1, BLOCK1804, nil)
		} else {
			res, _ = btcjson.MarshalResponse(1, BLOCK1805, nil)
		}
		w.Write(res)
	case "getblockhash":
		var res []byte
		if req.Params[0].(float64) == 1804 {
			res, _ = btcjson.MarshalResponse(1, "257e0ef983e245d26972b4effc959e8c5e819322d73dfce347fc7baf3c845a91", nil)
		} else {
			res, _ = btcjson.MarshalResponse(1, "32297a88e4f3bef3bcbdd22a2eef19b4671c4f3205f9483ba6e6def114ba6907", nil)
		}
		w.Write(res)
	case "getblockheader":
		var res []byte
		if req.Params[0].(string) == "257e0ef983e245d26972b4effc959e8c5e819322d73dfce347fc7baf3c845a91" {
			res, _ = btcjson.MarshalResponse(1, "0000002050c2f32c30615106cc58b01352a13e6f309d7e6f142ccbe58d37a709f81a3f4739825ad49375ac5ff5fc292df9ed518124035f4edcf9b48d0aaf49b29ef7770ef410415effff7f2000000000", nil)
		} else {
			res, _ = btcjson.MarshalResponse(1, "00000020915a843caf7bfc47e3fc3dd72293815e8c9e95fcefb47269d245e283f90e7e25062e6b40a9be5a5c1590dcff3d9e0a7cb80df890227a9b6c3989ebb00ef840051b11415effff7f2000000000", nil)
		}
		w.Write(res)
	case "getchaintips":
		resp := make(map[string]interface{})
		resp["height"] = 1805
		resp["hash"] = "32297a88e4f3bef3bcbdd22a2eef19b4671c4f3205f9483ba6e6def114ba6907"
		resp["branchlen"] = 0
		resp["status"] = "active"
		res, _ := btcjson.MarshalResponse(1, []interface{}{resp}, nil)
		w.Write(res)
	case "getrawtransaction":
		resp := make(map[string]interface{})
		outVal := make(map[string]interface{})
		outVal["hex"] = "002044978a77e4e983136bf1cca277c45e5bd4eff6a7848e900416daf86fd32c2743"
		out := make(map[string]interface{})
		out["scriptPubKey"] = outVal
		resp["vout"] = []interface{}{out}
		res, _ := btcjson.MarshalResponse(1, resp, nil)
		w.Write(res)
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
			hex.EncodeToString(append([]byte(common.CURRENT_HEADER_HEIGHT), utils2.GetUint64Bytes(utils.BTC_ID)...)) {
			rawBh, _ := hex.DecodeString("0000002050c2f32c30615106cc58b01352a13e6f309d7e6f142ccbe58d37a709f81a3f4739825ad49375ac5ff5fc292df9ed518124035f4edcf9b48d0aaf49b29ef7770ef410415effff7f2000000000")
			bh := new(wire.BlockHeader)
			_ = bh.BtcDecode(bytes.NewBuffer(rawBh), wire.ProtocolVersion, wire.LatestEncoding)

			sh := &MockStoredHeader{}
			sh.Header = *bh
			sh.Height = 1804
			sh.totalWork = big.NewInt(0)

			sink := new(common2.ZeroCopySink)
			sh.Serialization(sink)

			resp := map[string]interface{}{
				"error":  int64(0),
				"desc":   "SUCCESS",
				"result": common2.ToHexString(sink.Bytes()),
			}
			rb, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"error":   resp["error"],
				"desc":    resp["desc"],
				"result":  resp["result"],
				"id":      req.Id,
			})
			w.Write(rb)
		} else if req.Params[1].(string) == hex.EncodeToString(append(append([]byte(common.HEADER_INDEX),
			utils2.GetUint64Bytes(utils.BTC_ID)...), utils2.GetUint32Bytes(1804)...)) {
			hash, _ := chainhash.NewHashFromStr("257e0ef983e245d26972b4effc959e8c5e819322d73dfce347fc7baf3c845a91")
			resp := map[string]interface{}{
				"error":  int64(0),
				"desc":   "SUCCESS",
				"result": common2.ToHexString(hash.CloneBytes()),
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
	case client.RPC_GET_BLOCK_COUNT:
		if req.Id == "1" {
			resp := map[string]interface{}{
				"error":  int64(0),
				"desc":   "SUCCESS",
				"result": uint32(1),
			}
			rb, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"error":   resp["error"],
				"desc":    resp["desc"],
				"result":  resp["result"],
				"id":      req.Id,
			})

			w.Write(rb)
		} else {
			resp := map[string]interface{}{
				"error":  int64(0),
				"desc":   "SUCCESS",
				"result": uint32(2),
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
	case client.RPC_GET_SMART_CONTRACT_EVENT:
		events := make([]*common3.ExecuteNotify, 1)
		events[0] = &common3.ExecuteNotify{
			Notify: []common3.NotifyEventInfo{
				{
					States: []interface{}{"btcTxToRelay", 3, "", "tx"},
				},
			},
		}
		resp := map[string]interface{}{
			"error":  int64(0),
			"desc":   "SUCCESS",
			"result": events,
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

func (this *MockStoredHeader) Serialization(sink *common2.ZeroCopySink) {
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
	conf, err := btc_relayer.NewRelayerConfig("./conf.json")
	if err != nil {
		t.Fatal(err)
	}

	poly := poly_go_sdk.NewPolySdk()
	poly.NewRpcClient().SetAddress(conf.PolyObConf.PolyJsonRpcAddress)

	fmt.Println(utils.GetCurrHeightFromPoly(poly))
}
