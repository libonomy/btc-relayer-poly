package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	BTC_ID uint64 = 1
	HDR_LIMIT_PER_BATCH = 1000
)

var (
	SleepTime time.Duration = 10
)

type Header struct {
	Raw    []byte
	Height uint32
	Hash   string
}

type Headers []*Header

func (h Headers) Len() int {
	return len(h)
}

func (h Headers) Less(i, j int) bool {
	return h[i].Height < h[j].Height
}

func (h Headers) Swap(i, j int) {
	temp := h[i]
	h[i] = h[j]
	h[j] = temp
}

func (h Headers) GetSortedRawHeaders() [][]byte {
	sort.Sort(h)
	hdrs := make([][]byte, len(h))
	for i, v := range h {
		hdrs[i] = v.Raw
	}
	return hdrs
}

type CrossChainItem struct {
	Tx     []byte
	Proof  []byte
	Height uint32
	Txid   chainhash.Hash
}

func (cci *CrossChainItem) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, uint32(len(cci.Tx))); err != nil {
		return nil, err
	}
	buf.Write(cci.Tx)

	if err := binary.Write(&buf, binary.BigEndian, uint32(len(cci.Proof))); err != nil {
		return nil, err
	}
	buf.Write(cci.Proof)

	if err := binary.Write(&buf, binary.BigEndian, cci.Height); err != nil {
		return nil, err
	}
	buf.Write(cci.Txid[:])

	return buf.Bytes(), nil
}

func (cci *CrossChainItem) Deserialize(buf []byte) error {
	r := bytes.NewReader(buf)
	var lenTx uint32
	if err := binary.Read(r, binary.BigEndian, &lenTx); err != nil {
		return err
	}
	cci.Tx = make([]byte, lenTx)
	if _, err := r.Read(cci.Tx); err != nil {
		return err
	}

	var lenProof uint32
	if err := binary.Read(r, binary.BigEndian, &lenProof); err != nil {
		return err
	}
	cci.Proof = make([]byte, lenProof)
	if _, err := r.Read(cci.Proof); err != nil {
		return err
	}

	if err := binary.Read(r, binary.BigEndian, &cci.Height); err != nil {
		return err
	}
	txid := make([]byte, chainhash.HashSize)
	if _, err := r.Read(txid); err != nil {
		return err
	}
	if err := cci.Txid.SetBytes(txid); err != nil {
		return err
	}

	return nil
}

type CrossChainItemArr []*CrossChainItem

func (arr CrossChainItemArr) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(arr[:]))); err != nil {
		return nil, err
	}
	for _, v := range arr[:] {
		b, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(b))); err != nil {
			return nil, err
		}
		buf.Write(b)
	}

	return buf.Bytes(), nil
}

func (arr *CrossChainItemArr) Deserialize(buf []byte) error {
	r := bytes.NewReader(buf)

	var lenArr uint32
	if err := binary.Read(r, binary.BigEndian, &lenArr); err != nil {
		return err
	}
	res := make([]*CrossChainItem, lenArr)
	var lenItem uint32
	for i := uint32(0); i < lenArr; i++ {
		if err := binary.Read(r, binary.BigEndian, &lenItem); err != nil {
			return err
		}
		val := make([]byte, lenItem)
		if _, err := r.Read(val); err != nil {
			return err
		}
		res[i] = &CrossChainItem{}
		if err := res[i].Deserialize(val); err != nil {
			return err
		}
	}
	*arr = res
	return nil
}

type FromPolyItem struct {
	Tx string
}

type Request struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      int           `json:"id"`
}

type Response struct {
	Result interface{}       `json:"result"`
	Error  *btcjson.RPCError `json:"error"`
	Id     int               `json:"id"`
}

// Get tx in block; Get proof;
type RestCli struct {
	Addr string
	Cli  *http.Client
}

func NewRestCli(addr, user, pwd string) *RestCli {
	return &RestCli{
		Cli: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false,
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				Proxy: func(req *http.Request) (*url.URL, error) {
					req.SetBasicAuth(user, pwd)
					return nil, nil
				},
			},
			Timeout: time.Second * 300,
		},
		Addr: addr,
	}
}

func (cli *RestCli) sendPostReq(reqBody []byte) (*Response, error) {
	req, err := http.NewRequest("POST", cli.Addr, bytes.NewReader(reqBody))
	if err != nil {
		return nil, NetErr{fmt.Errorf("failed to new request: %v", err)}
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")

	resp, err := cli.Cli.Do(req)
	if err != nil {
		return nil, NetErr{fmt.Errorf("failed to post: %v", err)}
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, NetErr{fmt.Errorf("read response body error:%s", err)}
	}

	response := new(Response)
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, NetErr{fmt.Errorf("failed to unmarshal response: %v", err)}
	}
	return response, nil
}

func (cli *RestCli) GetProof(txids []string) (string, error) {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "gettxoutproof",
		Params:  []interface{}{txids},
		Id:      1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get proof: %v", err)
	}

	resp, err := cli.sendPostReq(req)
	if err != nil {
		return "", fmt.Errorf("failed to send post: %v", err)
	}
	if resp.Error != nil {
		if resp.Error.Code == -5 && resp.Error.Message == "Transaction not yet in block" {
			return "", NeedToRetryErr{fmt.Errorf(resp.Error.Message + ". Please check the setting of bitcoin " +
				"node, need -txindex")}
		}
		return "", fmt.Errorf("response shows failure: %v", resp.Error.Message)
	}

	return resp.Result.(string), nil
}

func (cli *RestCli) GetTxsInBlock(hash string) (*wire.MsgBlock, error) {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "getblock",
		Params:  []interface{}{hash, false},
		Id:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := cli.sendPostReq(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send post: %v", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("response shows failure: %v", resp.Error.Message)
	}
	bhex := resp.Result.(string)
	bb, err := hex.DecodeString(bhex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	block := new(wire.MsgBlock)
	err = block.BtcDecode(bytes.NewBuffer(bb), wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode block: %v", err)
	}

	return block, nil
}

func (cli *RestCli) GetTxsAndHeader(height, after uint32) ([]*wire.MsgTx, *wire.BlockHeader, string, error) {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "getblockhash",
		Params:  []interface{}{height},
		Id:      1,
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := cli.sendPostReq(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to send post: %v", err)
	}
	if resp.Error != nil {
		return nil, nil, "", fmt.Errorf("response shows failure: %v", resp.Error.Message)
	}

	hash := resp.Result.(string)
	if height > after {
		header, err := cli.GetHeader(hash)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to invoke GetHeader: %v", err)
		}
		return nil, header, hash, nil
	}
	blk, err := cli.GetTxsInBlock(hash)
	if err != nil {
		return nil, nil, "", fmt.Errorf("fail to invoke GetTxsInBlock: %v", err)
	}

	return blk.Transactions, &blk.Header, hash, nil
}

func (cli *RestCli) GetHeader(hash string) (*wire.BlockHeader, error) {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "getblockheader",
		Params:  []interface{}{hash, false},
		Id:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := cli.sendPostReq(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send post: %v", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("response shows failure: %v", resp.Error.Message)
	}

	str, ok := resp.Result.(string)
	if !ok {
		return nil, errors.New("result is not string type")
	}
	hb, err := hex.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode string: %v", err)
	}
	header := &wire.BlockHeader{}
	if err := header.BtcDecode(bytes.NewBuffer(hb), wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	return header, nil
}

func (cli *RestCli) GetCurrentHeightAndHash() (uint32, string, error) {
	reqTips, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "getchaintips",
		Params:  nil,
		Id:      1,
	})
	if err != nil {
		return 0, "", fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := cli.sendPostReq(reqTips)
	if err != nil {
		return 0, "", fmt.Errorf("failed to send post: %v", err)
	}
	if resp.Error != nil {
		return 0, "", fmt.Errorf("response shows failure: %v", resp.Error.Message)
	}

	m := resp.Result.([]interface{})[0].(map[string]interface{})
	return uint32(m["height"].(float64)), m["hash"].(string), nil
}

func (cli *RestCli) GetScriptPubKey(txid string, index uint32) (string, error) {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "getrawtransaction",
		Params:  []interface{}{txid, true},
		Id:      1,
	})
	if err != nil {
		return "", fmt.Errorf("[GetScriptPubKey] failed to marshal request: %v", err)
	}

	resp, err := cli.sendPostReq(req)
	if err != nil {
		return "", fmt.Errorf("[GetScriptPubKey] failed to send post: %v", err)
	}
	if resp.Error != nil {
		if resp.Error.Code == -5 {
			return "", NeedToRetryErr{fmt.Errorf(resp.Error.Message + ". Please check the setting of bitcoin " +
				"node, need -txindex")}
		}
		return "", fmt.Errorf("[GetScriptPubKey] response shows failure: %v", resp.Error.Message)
	}

	return resp.Result.(map[string]interface{})["vout"].([]interface{})[index].(map[string]interface{})["scriptPubKey"].(map[string]interface{})["hex"].(string), nil
}

func (cli *RestCli) BroadcastTx(tx string) (string, error) {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "sendrawtransaction",
		Params:  []interface{}{tx},
		Id:      1,
	})
	if err != nil {
		return "", fmt.Errorf("[BroadcastTx] failed to marshal request: %v", err)
	}

	resp, err := cli.sendPostReq(req)
	if err != nil {
		return "", fmt.Errorf("[BroadcastTx] failed to send post: %v", err)
	}
	if resp.Error != nil {
		switch resp.Error.Code {
		case btcjson.ErrRPCTxError:
			if NeedRetry(resp.Error.Message) {
				return "", NeedToRetryErr{
					Err: fmt.Errorf("[BroadcastTx] response shows failure and retry: code:%d; %v", resp.Error.Code, resp.Error.Message),
				}
			}
			fallthrough
		case btcjson.ErrRPCTxRejected:
			return "", NeedToRetryErr{
				Err: fmt.Errorf("[BroadcastTx] response shows failure and retry: code:%d; %v", resp.Error.Code, resp.Error.Message),
			}
		default:
			return "", fmt.Errorf("[BroadcastTx] response shows failure: %v", resp.Error.Message)
		}
	}

	return resp.Result.(string), nil
}

func (cli *RestCli) IsHeaderReady(height uint32) error {
	req, err := json.Marshal(Request{
		Jsonrpc: "1.0",
		Method:  "getblockhash",
		Params:  []interface{}{height},
		Id:      1,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}
	resp, err := cli.sendPostReq(req)
	if err != nil {
		return fmt.Errorf("failed to send post: %v", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("response shows failure: %v", resp.Error.Message)
	}
	return nil
}

type NeedToRetryErr struct {
	Err error
}

func (err NeedToRetryErr) Error() string {
	return err.String()
}

func (err *NeedToRetryErr) String() string {
	return err.Err.Error()
}

type NetErr struct {
	Err error
}

func (err NetErr) Error() string {
	return err.Err.Error()
}

func NeedRetry(msg string) bool {
	if strings.Contains(msg, "missing-inputs") {
		return true
	}
	return false
}

func GetCurrHeightFromPoly(poly *poly_go_sdk.PolySdk) (uint32, string, error) {
	best, err := poly.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
		append([]byte(mscom.CURRENT_HEADER_HEIGHT), utils.GetUint64Bytes(BTC_ID)...))
	if err != nil {
		return 0, "", err
	}
	bestSh := new(btc.StoredHeader)
	if err = bestSh.Deserialization(common.NewZeroCopySource(best)); err != nil {
		return 0, "", fmt.Errorf("failed to deserialize best: %v", err)
	}

	return bestSh.Height, bestSh.Header.BlockHash().String(), nil
}

func GetHeaderHashFromPoly(poly *poly_go_sdk.PolySdk, height uint32) (string, error) {
	hashStore, err := poly.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
		append(append([]byte(mscom.HEADER_INDEX), utils.GetUint64Bytes(BTC_ID)...), utils.GetUint32Bytes(height)...))
	if err != nil {
		return "", err
	}
	//hashBs, err := states.GetValueFromRawStorageItem(hashStore)
	//if err != nil {
	//	return "", err
	//}
	hash, err := chainhash.NewHash(hashStore)
	if err != nil {
		return "", err
	}
	return hash.String(), err
}

func Wait(dura time.Duration) {
	t := time.NewTimer(dura)
	<-t.C
	t.Stop()
}

func SetUpPoly(poly *poly_go_sdk.PolySdk, rpcAddr string) error {
	poly.NewRpcClient().SetAddress(rpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}