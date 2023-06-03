本实验的主要目的是进一步理解区块链的数据结构，实现基于POW共识算法出块，实现比特币上的账户创建和查询，理解UTXO的基本使用方法，以及实现区块链与数据库的交互。以下将对各部分进行详细介绍。

## UTXO池部分

UTXO（Unspent Transaction Output）是指未花费的交易输出。在比特币中，每个交易输出都会生成一个UTXO，当这个UTXO被用于支付时，它就会被标记为已花费。

`FindUnspentOutputs`函数的作用是找到给定公钥哈希和金额的所有未花费输出。它返回未花费输出的总金额以及一个包含交易ID和输出索引的映射，这些输出可以被用于支付。

```go
// FindSpendableOutputs finds and returns unspent outputs to reference in inputs
func (u UTXOSet) FindUnspentOutputs(pubkeyHash []byte, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0
	db := u.Blockchain.db
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			txID := hex.EncodeToString(k)
			outs := DeserializeOutputs(v)
			for outIdx, out := range outs.Outputs {
				if out.IsLockedWithKey(pubkeyHash) && accumulated < amount {
					accumulated += out.Value
					unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return accumulated, unspentOutputs
}
```

## POW部分

POW（Proof of Work）是一种共识算法，用于通过计算难题来验证交易并创建新的区块。在比特币中，POW算法是通过计算SHA256哈希值来完成的。

`Validate`函数用于验证一个区块的工作量证明是否有效。它会将区块的头部哈希和目标难度值传入，计算出对应的哈希值，并判断是否小于目标难度值。

`Run`函数用于执行工作量证明计算。它会不断地尝试计算哈希值，直到找到一个小于目标难度值的哈希值为止。计算完成后，它会返回计算所用的时间和计算得到的哈希值。

```go
// Run performs a proof-of-work
func (pow *ProofOfWork) Run() (int64, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := int64(0)
	for nonce < int64(maxNonce) {
		data := bytes.Join(
			[][]byte{
				IntToHex(pow.block.Header.Version),
				pow.block.Header.PrevBlockHash[:],
				pow.block.Header.MerkleRoot[:],
				IntToHex(pow.block.Header.Timestamp),
				IntToHex(targetBits),
				IntToHex(nonce),
			},
			[]byte{},
		)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	return nonce, hash[:]
}

// Validate validates block's PoW
func (pow *ProofOfWork) Validate() bool {
	data := bytes.Join(
		[][]byte{
			IntToHex(pow.block.Header.Version),
			pow.block.Header.PrevBlockHash[:],
			pow.block.Header.MerkleRoot[:],
			IntToHex(pow.block.Header.Timestamp),
			IntToHex(targetBits),
			IntToHex(pow.block.Header.Nonce),
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
	var hashInt big.Int
	hashInt.SetBytes(hash[:])
	return hashInt.Cmp(pow.target) == -1
}
```



## Blockchain部分

区块链是由一系列块组成的数据结构，每个块包含一些交易和指向前一个块的指针。`MineBlock`函数用于创建一个新块，并将其添加到区块链中。该函数需要传入要包含的交易列表，并执行POW算法来生成工作量证明。

`FindUTXO`函数用于查找所有未花费的交易输出。它会遍历整个区块链，并收集所有未花费的UTXO。返回值是一个字典，其中键是交易ID，值是该交易中未花费的输出列表。

```go
// MineBlock mines a new block with the provided transactions
func (bc *Blockchain) MineBlock(transactions []*Transaction) *Block {
	var lastHash [32]byte
	for _, tx := range transactions {
		if bc.VerifyTransaction(tx) != true {
			log.Panic("ERROR: Invalid transaction")
		}
	}
	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		copy(lastHash[:], b.Get([]byte("l")))

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	newBlock := NewBlock(transactions, lastHash)
	pow := NewProofOfWork(newBlock)
	nonce, _ := pow.Run()
	newBlock.Header.Nonce = nonce
	err = bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		err := b.Put(newBlock.CalCulHash(), newBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}
		err = b.Put([]byte("l"), newBlock.CalCulHash())
		if err != nil {
			log.Panic(err)
		}
		bc.tip = newBlock.CalCulHash()
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return newBlock
}
func (bc *Blockchain) FindUTXO() map[string]TXOutputs {
	UTXO := make(map[string]TXOutputs)
	spentTXOs := make(map[string][]int)
	bci := bc.Iterator()
	for {
		block := bci.Next()
		for _, tx := range block.GetTransactions() {
			txID := hex.EncodeToString(tx.ID)
			// Handle outputs
			outputs := TXOutputs{}
			for outIdx, out := range tx.Vout {
				// If output is already spent, skip it
				if spentTXOs[txID] != nil {
					if spentTXOs[txID][outIdx] != 0 {
						continue
					}
				}
				// If output is not spent, add it to UTXO set
				outputs.Outputs = append(outputs.Outputs, out)
			}
			if len(outputs.Outputs) > 0 {
				UTXO[txID] = outputs
			}
			// Handle inputs
			if tx.IsCoinBase() == false {
				for _, vin := range tx.Vin {
					inTxID := hex.EncodeToString(vin.Txid)
					spentTXOs[inTxID] = append(spentTXOs[inTxID], vin.Vout)
				}
			}
		}
		if block.GetPrevhash() == [32]byte{} {
			break
		}
	}
	return UTXO
}
```



## Transaction部分

交易是在区块链上转移价值的基本单位，它包含输入和输出。输入指向之前的交易输出，输出指定要转移的价值和接收方地址。

`NewUTXOTransaction`函数用于创建一个新的UTXO交易。它需要传入发送方和接收方的公钥哈希、要转移的金额以及UTXO集合。函数首先会创建一个输入，指向之前的UTXO，然后创建一个输出，指定转移的金额和接收方地址。如果发送方的余额不足，则会返回错误。否则，函数会创建一个新的交易并返回。

```go
// NewUTXOTransaction creates a new transaction
func NewUTXOTransaction(from, to []byte, amount int, UTXOSet *UTXOSet) *Transaction {
	var inputs []TXInput
	var outputs []TXOutput
	Wallets, _ := NewWallets()
	Wallet := Wallets.GetWallet(from)
	pubkeyHash := base58.Decode(string(from))
	pubkeyHash = pubkeyHash[1 : len(pubkeyHash)-4]
	// Find unspent transaction outputs belonging to the sender's addresses
	acc, validOutputs := UTXOSet.FindUnspentOutputs(pubkeyHash, amount)
	if acc < amount {
		log.Panic("ERROR: Not enough funds")
	}
	// Create inputs from the valid outputs
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			log.Panic(err)
		}
		for _, out := range outs {
			input := TXInput{txID, out, nil, Wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}
	pubkeyHash = base58.Decode(string(to))
	pubkeyHash = pubkeyHash[1 : len(pubkeyHash)-4]
	// Create outputs for the recipient's address and possibly for the sender's change address
	outputs = append(outputs, TXOutput{amount, pubkeyHash})
	if acc > amount {
		outputs = append(outputs, TXOutput{acc - amount, pubkeyHash})
	}
	// Create transaction
	tx := Transaction{nil, inputs, outputs}
	// Sign the transaction
	tx.SetID()
	UTXOSet.Blockchain.SignTransaction(&tx, Wallet.PrivateKey)
	return &tx
}
```



