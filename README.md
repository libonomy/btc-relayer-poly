# BTC Relayer


### This repository is under-development and hasnt reached towards it's beta version. Therefore kindly keep your local repository updated with the release.
​ BTC Relayer is the communication bridge between the Bitcoin network and the alliance chain in the cross-chain eco-system, and is responsible for forwarding BTC cross-chain transactions to the alliance chain. This is the first step in the cross-chain. Its main functions include two parts. The first is to monitor the Bitcoin network, which forwards BTC transactions that will be cross-chain to other chains to the consortium chain; the second is to monitor the consortium chain and broadcast the transactions to the Bitcoin network to the Bitcoin network .

​	Running

```shell
go build -o run_btc_relayer run.go 
```

​ Path Configuration

```
run_btc_relayer -conf-file=/path/to/conf.json -log-path=/path/to/log/ 
```

​	Changes to be added in the configuration file
​ The relayer will serve as a mean to interconnect libonomy with the other master chains. The repository serves as the practical implementation of the blockchain relayer such as poly network and its extension. The repository will further be extended to interact with ETH,COSMOS,PEGASYS and POLY NETWORK
