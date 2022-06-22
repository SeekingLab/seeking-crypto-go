package paillier

import (
	"math/big"
)

//包含paillier的同态加法和同态数乘

//同态加法
func AddHomom(pk *PublicKey, c1 *big.Int, c2 *big.Int, ) (newC *big.Int) {
	c1c2 := new(big.Int).Mul(c1, c2)
	nn := new(big.Int).Mul(pk.N, pk.N)
	newC = new(big.Int).Mod(c1c2, nn)
	return
}

//同态数乘
func NumMulHomom(pk *PublicKey, c *big.Int, num *big.Int) (newC *big.Int) {
	var i int64
	var tmp = new(big.Int).SetInt64(1)
	for i = 0; i < num.Int64(); i++ {
		tmp = new(big.Int).Mul(tmp, c)
	}
	newC = tmp
	return
}
