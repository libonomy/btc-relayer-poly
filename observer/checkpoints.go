package observer

type Checkpoint struct {
	Height uint32
}

var btcCheckPoints map[string]*Checkpoint
var polyCheckPoints map[string]*Checkpoint

func init() {
	btcCheckPoints = make(map[string]*Checkpoint)
	polyCheckPoints = make(map[string]*Checkpoint)

	btcCheckPoints["regtest"] = &Checkpoint{
		Height: 0,
	}
	btcCheckPoints["mainnet"] = &Checkpoint{
		Height: 602805, // need to set
	}
	btcCheckPoints["testnet3"] = &Checkpoint{
		Height: 1610270,
	}

	polyCheckPoints["testnet"] = &Checkpoint{
		Height: 1,
	}
	polyCheckPoints["regtest"] = &Checkpoint{
		Height: 1,
	}
}
