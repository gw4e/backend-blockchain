## Pycotr Backend
### _A blockchain backend naive implementaion that helps me to learn what is blockchain_

### Pycotr <img src="http://github.com/gw4e/frontend-blockchain/blob/main/public/images/brand-white.png?raw=true" data-canonical-src="http://github.com/gw4e/frontend-blockchain/blob/main/public/images/brand-white.png" width="30" height="30" /> BackEnd


A Decentralized Application is a piece of software that has its backend code running on a decentralized peer to peer network.  This project holds this backend and is the part that connects with a [frontend](https://github.com/gw4e/frontend-blockchain) to provide its necessary function.

## Features
Each backend nodes (here called miners) in the network will:

- Receive transactions from the front end
- Broadcast these transactions to other peer miners
- Store these transactions in a pool of transactions. This pool is a collection of unconfirmed transactions on the backend peer network that are waiting to be processed.
- Mine these transactions at a certain rate to add block of transactions in its blockchain.
  By selecting transactions and adding them to their block, miners create a block of transactions. To add this block of transactions to the blockchain, the block first needs a signature (also referred to as a ‘proof of work’). This signature is created by solving a mathematical problem that is unique to each block of transactions.
- Ask for consensus. The term "consensus" means that all nodes in the network must agree on an identical version of the blockchain. In a way, the consensus mechanism of a blockchain is an internal and automatic audit of its network.
- Each node mines blocks at a regular rate and the winner node is rewarded (see below the Mining section)

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
- Update the GENESIS_FILE_LOCATION env variable in the .env file. Set this value to **<YOUR_CHECKOUT_DIRECTORY>/backend-blockchain/src/blockchain/genesis** 
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
If you want to dig in the source code start with **src/server/main.py**

## Note:


### Proof-of-Work
Proof of work is the consensus algorithm used in major blockchains. In POW, the miners calculate a complex mathematical puzzle, 
called the NONCE. The calculated nonce should be less than the previous nonce value present in the blockchain. 
POW requires significant computational resources. The computational resource for POW is extremely high in a real word.
In this implementation, the POW is not very costly for demonstration/learning/training purpose, and it does not rely on 
the previous block Nonce value.
````
```
def proof_work(self, difficulty: int):
  self._nonce = 1
  self._hash = self.calculate_hash()
  while (self._hash.hexdigest()[0:difficulty]) != "".zfill(difficulty):
  self._nonce += 1
  self._hash = self.calculate_hash()
```
````

### Consensus or The Longest Chain rule
The majority decision is represented by the longest chain, which has the greatest proof-of-work effort invested in it. 
All the nodes trust the longest chain in a blockchain without trusting each other directly.
Building any block requires energy. The chain with the longest block needs the most power to create. The algorithm discards the shorter chains, 
and the longest chain is adopted.

````
```
    def update_block_chain_from_consensus(self):
        logging.info("update_block_chain_from_consensus started")
        block_chains = self._ask_other_nodes()
        logging.info(f"update_block_chain_from_consensus _ask_other_nodes gives {len(block_chains)}")
        response = self._get_longest_block_chain(block_chains)
        longest_chain = response["chain"]
        pending_transactions = response["pending_transactions"]
        if longest_chain is not None and pending_transactions is not None:
            logging.info(f"longest_chain size : {len(longest_chain)}")
            source_blockchain_id = response["source_blockchain_id"]
            self._blockchain.update(longest_chain, pending_transactions, source_blockchain_id)
            return {
                "status": BlockChain.UPDATED,
            }
        return {
            "status": BlockChain.NO_UPDATE,
        }
```
````

In this implementation, to simulate the various power of the nodes, a rate mining frequency is set at node startup
- Node 1 : "http://localhost:3001" --> 5sec
- Node 2 : "http://localhost:3002" --> 10sec
- Node 3 : "http://localhost:3003" --> 15sec

This leads the Node 1 to always win the consensus whenever one of the other nodes send their blockcahin to challenge it since
it will always have the longest one. After 1 minute, of having nodes running , we should have something like :
- Node 1 : "http://localhost:3001" --> 12 blocks
- Node 2 : "http://localhost:3002" --> 6 blocks
- Node 3 : "http://localhost:3003" --> 4 blocks


### Mining
This implementation is of course a naive one and many problems still need to be solved.
- A consensus algorithm is far more complex than the one implemented :-)
- How to manage different nodes running with different versions of this backend ? 
- How to increase the complexity of the mining problem while nodes are running ?
- Whenever a consensus is triggered, if a node see that the proposed blockchain is valid and longer that its own 
blockchain it should stop mining 
- ...

In this implementation, all transactions in the pool are taken to be mined, instead of selecting some of them depending on some fee
````
```
  def _thread_function(self, bc: BlockChain, delay: int, name: str):
      logging.info("Miner named %s: starting", name)
      self._running = True
      self._stop_event.clear()
      while self.is_running():
          try:
              logging.info("Miner named %s: will pause", name)
              self._stop_event.wait(delay)
              logging.info("Miner named %s: pause resumed", name)
              if self._stop_event.is_set():
                  logging.info("Miner named %s: is required to stop", name)
                  break
              logging.info("Miner named %s: will mine", name)
              bc.mine_pending_transactions(True)
              logging.info(" %s: mined", name)
          except Exception as err:
              logging.info("Worker %s: failed while mining", err)
      self._mining_thread = None
  //
  def mine_pending_transactions(self, all_elements=False) -> bool:
      with self._lock:
          logging.info("mine_pending_transactions ---> Choose transactions to mine")
          transactions = self.choose_transactions(all_elements)
      ...
      ...
  //
  def choose_transactions(self, all_elements: bool) -> List[Transaction]:
    size = self._pool_transactions.size()
    if size > 0:
      count = size if all_elements else random.randint(0, size - 1)
      return self._pool_transactions.slice(count)
    return []
```
````

## Disclaimer:
This project is **only** for educational or learning purpose. Use at your own risk.

## License
MIT



