# Pycotr Backend
## _A blockchain backend naive implementaion that helps me to learn what is blockchain_

[![N|Solid](https://cldup.com/dTxpPi9lDf.thumb.png)](https://nodesource.com/products/nsolid)

A Decentralized Application is a piece of software that has its backend code running on a decentralized peer to peer network.  This project holds this backend and is the part that connects with a frontend to provide its necessary function (see ....).

## Features
Each backend nodes (here called miners) in the network will:

- Receive transactions from the front end
- Broadcast these transactions to other peer miners
- Store these transactions in a pool of transactions. This pool is a collection of unconfirmed transactions on the backend peer network that are waiting to be processed.
- Mine these transactions at a certain rate to add block of transactions in its blockchain.
  By selecting transactions and adding them to their block, miners create a block of transactions. To add this block of transactions to the blockchain, the block first needs a signature (also referred to as a ‘proof of work’). This signature is created by solving a mathematical problem that is unique to each block of transactions.
- Ask for consensus. The term "consensus" means that all nodes in the network must agree on an identical version of the blockchain. In a way, the consensus mechanism of a blockchain is an internal and automatic audit of its network.


## Tech

Pycotr Backend uses a number of techno. to work properly:

- [Python] - To write this backend
- [Flask] - As a backend server
- [PyTest] - For Unit and Integration tests
- [Docker] - For the runtime

## Installation

PyCotr Backend requires [Python 3.7](https://www.python.org/) and [Docker](https://www.docker.com/products/docker-desktop/) for local development.

Install the runtime and starts the netowrk nodes

- Install Docker Desktop
- Checkout the project
- Start the network of nodes by running **start_nodes.sh**
- To stop the network, run **stop_nodes.sh**

Once the network of nodes is started, you cannot do something very useful yet. You need to install and run the front-end.
**At startup each node does not know its peers. To make it a real network you have to use the front-end to configure it and make sure they all know each other**.
If you don't do that, you won't have any transactions broadcasting and no consenus will occur.

## Testing
- Install Python 3.7 (at least)
- Configure the project it so that it uses Python 3.7
- Stop the network if running, with **stop_nodes.sh**
- Execute unit tests and integration tests by running **run_tests.sh**

## Debugging
Start the **server.py** file in debug mode

## Genesis Block
The genesis block is the name given to the first block created on a given blockchain. It has the particularity of not being preceded by any other block and of giving us indications on the exact moment when the first transaction on the network took place as well as the amount of the latter.
There is no persistence of the blockchain. If you stop the nodes, you will loose all transactions stored in the blockchain. This is an intented behavior. At startup of the node, the genesis block is read from a json file. This file is generated by **run_generator.sh** and is commited in the project surce file. It should be regenerated if the model changes.

## Source code
If you want to dig in the source code starts with **src/server/main.py**

## Note:
This implementation is of course a naive one and many problems still need to be solved.
What would happen if one of the node stops and restarts with a new version of the implementtaion ?
How to increase the complexity of the mining problem while nodes are running ?
Currently, all transactions in the pool are taken to be mined, instead of selecting some of them
...
...



## Disclaimer:
This project is **only** for educational or learning purpose. Use at your own risk.

## License
MIT



