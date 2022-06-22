package paillier

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPaillier(t *testing.T){

	var key Key
	var err error

	key, err = KeyPairGen(18)
	if err != nil {
		t.Error("KeyPairGen err")
	}

	m1 := new(big.Int).SetInt64(int64(11))
	c, err1 := Encrypt(&(key.PubK), m1)
	if err1 != nil {
		t.Error("Encrypt err")
	}

	m2, err2 := Decrypt(&(key.PubK), &(key.PrivK), c)
	if err2 != nil {
		t.Error("Decrypt err")

	}

	if m1.Int64() != m2.Int64() {
		t.Error("Decrypt err")
	} else {
		fmt.Println("解密成功")
		fmt.Printf("m1=%v, m2=%v,c=%v pk.G=%v, pk.n=%v, sk.lambda=%v, sk.mu=%v", m1, m2, c, key.PubK.G, key.PubK.N, key.PrivK.Lambda, key.PrivK.Mu)
		fmt.Println()
	}

	m3 := new(big.Int).SetInt64(int64(22))
	c3, err3 := Encrypt(&(key.PubK), m3)
	if err3 != nil {
		fmt.Println(err3)
	}
	c4 := AddHomom(&key.PubK, c, c3)

	m4, err4 := Decrypt(&(key.PubK), &(key.PrivK), c4)
	if err4 != nil {
		fmt.Println(err4)
	}
	fmt.Println("同态加密后的m4=", m4)

	c5 := NumMulHomom(&(key.PubK), c, new(big.Int).SetInt64(5))
	m5, err5 := Decrypt(&(key.PubK), &(key.PrivK), c5)
	if err5 != nil {
		fmt.Println(err5)
	}
	fmt.Println("同态加密后的m5=", m5)

}
