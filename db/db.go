package db

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/evdatsion/btc-relayer-poly/log"
	"github.com/evdatsion/btc-relayer-poly/utils"
	"math"
	"path"
	"strings"
	"sync"
)

var (
	BKTRetry          = []byte("retry")
	BKTBtcLastHeight  = []byte("btclast")
	BKTPolyLastHeight = []byte("polylast")
	BKTTxNeedToRetry  = []byte("retrytx")
	KEYBtcLastHeight  = []byte("btclast")
	KEYPolyLastHeight = []byte("polylast")
	KEYMinHeight      = []byte{0x0}
)

type RetryDB struct {
	rwlock        *sync.RWMutex
	db            *bolt.DB
	dbPath        string
	retryDuration int
	retryTimes    []byte
	maxReadSize   uint64
}

func NewRetryDB(filePath string, times, retryDuration int, maxReadSize uint64) (*RetryDB, error) {
	if !strings.Contains(filePath, ".bin") {
		filePath = path.Join(filePath, "retry.bin")
	}
	if times < 0 {
		return nil, fmt.Errorf("retry time must greater than or equal to 0, yours %d", times)
	}
	if retryDuration <= 0 {
		return nil, fmt.Errorf("retry duration must greater than 0, yours %d", retryDuration)
	}

	r := new(RetryDB)
	db, err := bolt.Open(filePath, 0644, &bolt.Options{InitialMmapSize: 500000})
	if err != nil {
		return nil, err
	}

	r.db = db
	r.rwlock = new(sync.RWMutex)
	r.dbPath = filePath
	r.retryDuration = retryDuration
	r.retryTimes = make([]byte, 2)
	r.maxReadSize = maxReadSize
	binary.LittleEndian.PutUint16(r.retryTimes, uint16(times))

	if err = db.Update(func(btx *bolt.Tx) error {
		if _, err := btx.CreateBucketIfNotExists(BKTRetry); err != nil {
			return err
		}
		if _, err = btx.CreateBucketIfNotExists(BKTTxNeedToRetry); err != nil {
			return err
		}
		if _, err := btx.CreateBucketIfNotExists(BKTBtcLastHeight); err != nil {
			return err
		}
		if _, err := btx.CreateBucketIfNotExists(BKTPolyLastHeight); err != nil {
			return err
		}

		bkt := btx.Bucket(BKTTxNeedToRetry)
		initVal := make([]byte, 4)
		binary.BigEndian.PutUint32(initVal, math.MaxUint32)
		if err := bkt.Put(KEYMinHeight, initVal); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *RetryDB) setHeight(height uint32, bucket, key []byte) error {
	r.rwlock.Lock()
	defer r.rwlock.Unlock()
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, height)

	return r.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucket)
		err := bucket.Put(key, val)
		if err != nil {
			return err
		}
		return nil
	})
}

func (r *RetryDB) getHeight(bucket, key []byte) uint32 {
	r.rwlock.RLock()
	defer r.rwlock.RUnlock()
	var height uint32
	_ = r.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucket)
		val := bucket.Get(key)
		if val == nil {
			height = 0
			return nil
		}
		height = binary.LittleEndian.Uint32(val)
		return nil
	})

	return height
}

func (r *RetryDB) SetBtcHeight(height uint32) error {
	return r.setHeight(height, BKTBtcLastHeight, KEYBtcLastHeight)
}

func (r *RetryDB) GetBtcHeight() uint32 {
	return r.getHeight(BKTBtcLastHeight, KEYBtcLastHeight)
}

func (r *RetryDB) SetPolyHeight(height uint32) error {
	return r.setHeight(height, BKTPolyLastHeight, KEYPolyLastHeight)
}

func (r *RetryDB) GetPolyHeight() uint32 {
	return r.getHeight(BKTPolyLastHeight, KEYPolyLastHeight)
}

func (r *RetryDB) Put(tx string) error {
	r.rwlock.Lock()
	defer r.rwlock.Unlock()

	txb, err := hex.DecodeString(tx)
	if err != nil {
		return err
	}

	return r.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTRetry)
		err := bucket.Put(txb, r.retryTimes)
		if err != nil {
			return err
		}
		return nil
	})
}

func (r *RetryDB) GetAll() ([]string, error) {
	mtxArr := make([]string, 0)
	var err error
	r.rwlock.Lock()
	defer r.rwlock.Unlock()

	if binary.LittleEndian.Uint16(r.retryTimes) > 0 {
		err = r.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(BKTRetry)
			valArr := make([]uint16, 0)
			totalSize := uint64(0)
			err := bucket.ForEach(func(k, v []byte) error {
				mtxArr = append(mtxArr, hex.EncodeToString(k))
				valArr = append(valArr, binary.LittleEndian.Uint16(v)-1)
				if totalSize += uint64(len(k)); totalSize > r.maxReadSize {
					return OverReadSizeErr{
						Err: fmt.Errorf("read %d bytes from db, but oversize %d", totalSize, r.maxReadSize),
					}
				}
				return nil
			})
			if err != nil {
				log.Errorf("GetAll, %v", err)
			}
			for i, mtx := range mtxArr {
				k, _ := hex.DecodeString(mtx)
				if valArr[i] <= 0 {
					err := bucket.Delete(k)
					if err != nil {
						return err
					}
				} else {
					val := make([]byte, 2)
					binary.LittleEndian.PutUint16(val, valArr[i])
					err := bucket.Put(k, val)
					if err != nil {
						return err
					}
				}
			}

			return nil
		})
	} else {
		err = r.db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(BKTRetry)
			totalSize := uint64(0)
			err := bucket.ForEach(func(k, v []byte) error {
				mtxArr = append(mtxArr, hex.EncodeToString(k))
				if totalSize += uint64(len(k)); totalSize > r.maxReadSize {
					return OverReadSizeErr{
						Err: fmt.Errorf("read %d bytes from db, but oversize %d", totalSize, r.maxReadSize),
					}
				}
				return nil
			})
			if err != nil {
				log.Errorf("GetAll, %v", err)
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	if len(mtxArr) == 0 {
		return nil, errors.New("no tx in db")
	}

	return mtxArr, nil
}

func (r *RetryDB) Del(k string) error {
	r.rwlock.Lock()
	defer r.rwlock.Unlock()

	kb, err := hex.DecodeString(k)
	if err != nil {
		return err
	}
	return r.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTRetry)
		err := bucket.Delete(kb)
		if err != nil {
			return err
		}
		return nil
	})
}

func (r *RetryDB) PutCCI(item *utils.CrossChainItem) error {
	r.rwlock.Lock()
	defer r.rwlock.Unlock()

	key := make([]byte, 4)
	binary.BigEndian.PutUint32(key, item.Height)
	if err := r.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(BKTTxNeedToRetry)
		arrb := bkt.Get(key)
		var arr utils.CrossChainItemArr
		if arrb == nil {
			arr = []*utils.CrossChainItem{item}
		} else {
			if err := arr.Deserialize(arrb); err != nil {
				return err
			}
			arr = append(arr[:], item)
		}
		newVal, err := arr.Serialize()
		if err != nil {
			return err
		}
		if err := bkt.Put(key, newVal); err != nil {
			return err
		}
		minb := bkt.Get(KEYMinHeight)
		min := binary.BigEndian.Uint32(minb)
		if min > item.Height {
			if err := bkt.Put(KEYMinHeight, key); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (r *RetryDB) GetCCI(height uint32) (utils.CrossChainItemArr, error) {
	r.rwlock.RLock()
	defer r.rwlock.RUnlock()

	var arr utils.CrossChainItemArr
	key := make([]byte, 4)
	binary.BigEndian.PutUint32(key, height)
	if err := r.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(BKTTxNeedToRetry)
		arrb := bkt.Get(key)
		if err := arr.Deserialize(arrb); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return arr, nil
}

func (r *RetryDB) GetCCIUnderHeightAndDel(height uint32) ([]*utils.CrossChainItem, error) {
	r.rwlock.Lock()
	defer r.rwlock.Unlock()

	res := make([]*utils.CrossChainItem, 0)
	if err := r.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(BKTTxNeedToRetry)
		minb := bkt.Get(KEYMinHeight)
		min := binary.BigEndian.Uint32(minb)

		key := make([]byte, 4)
		for i := min; i <= height; i++ {
			binary.BigEndian.PutUint32(key, i)
			val := bkt.Get(key)
			if val == nil {
				continue
			}
			var arr utils.CrossChainItemArr
			if err := arr.Deserialize(val); err != nil {
				return err
			}
			res = append(res, arr...)
			if err := bkt.Delete(key); err != nil {
				return err
			}
		}

		min = uint32(math.MaxUint32)
		if err := bkt.ForEach(func(k, v []byte) error {
			if bytes.Equal(k, KEYMinHeight) {
				return nil
			}
			h := binary.BigEndian.Uint32(k)
			if h < min {
				min = h
			}
			return nil
		}); err != nil {
			return err
		}
		minb = make([]byte, 4)
		binary.BigEndian.PutUint32(minb, min)
		if err := bkt.Put(KEYMinHeight, minb); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (r *RetryDB) GetMinHeight() uint32 {
	r.rwlock.RLock()
	defer r.rwlock.RUnlock()

	min := uint32(math.MaxUint32)
	_ = r.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(BKTTxNeedToRetry)
		minb := bkt.Get(KEYMinHeight)
		if minb == nil {
			return nil
		}
		min = binary.BigEndian.Uint32(minb)
		return nil
	})

	return min
}

type OverReadSizeErr struct {
	Err error
}

func (err OverReadSizeErr) Error() string {
	return err.Err.Error()
}
