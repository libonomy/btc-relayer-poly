# BTC Relayer


### NOTE: This repository is under development and has not reached beta version yet. Kindly keep your local repository updated with the release.
​BTC Relayer is the communication bridge between the Bitcoin-network and the alliance-chain in the cross-chain ecosystem. BTC Relayer is responsible for forwarding   BTC cross-chain transactions to the alliance-chain. This is the first step in the cross-chain. Main functions include two parts:
- The first part is to monitor the Bitcoin-network, which forwards BTC-transactions, that will be crosschained to other chains, to the consortium-chain. 
- The second part is to monitor the consortium-chain and broadcast the transactions to the Bitcoin-network.

​	Running

```shell
go build -o run_btc_relayer run.go 
```

​ Path Configuration

```
run_btc_relayer -conf-file=/path/to/conf.json -log-path=/path/to/log/ 
```

​ Changes to be added in the configuration file. The relayer will serve as a mean to interconnect Libonomy with the other masterchains. The repository serves as the practical implementation of the blockchain-relayer such as polynetwork and its extension. The repository will further be extended to interact with ETH, COSMOS, PEGASYS and POLY NETWORK.
