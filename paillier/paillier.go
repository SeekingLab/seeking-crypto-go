package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	//"openmpc/cryptofun-master/prime"
)

//Paillier加密系统，是1999年paillier发明的概率公钥加密系统。
//基于复合剩余类的困难问题。该加密算法是一种同态加密，满足加法和数乘同态。

var one = new(big.Int).SetInt64(1)
var zero = new(big.Int).SetInt64(0)

//密钥结构体
type Key struct {
	PubK  PublicKey
	PrivK PrivKey
}

//公钥
type PublicKey struct {
	N *big.Int
	G *big.Int
}

//私钥
type PrivKey struct {
	Lambda *big.Int
	Mu     *big.Int
}

//lcm函数，求a和b的最小公倍数
func Lcm(a *big.Int, b *big.Int) (lcm *big.Int) {
	// a*b = gcd(a,b) * lcm(a,b)
	ab := new(big.Int).Mul(a, b)
	gcd := new(big.Int).GCD(nil, nil, a, b)
	lcm = new(big.Int).Div(ab, gcd)
	fmt.Printf("ab=%v, gcd=%v, lcm=%v",ab,gcd,lcm)
	fmt.Println()
	return
}

//l(x)=(x-1)/n
func L(a *big.Int, n *big.Int) (l *big.Int) {
	//one := new(big.Int).SetInt64(1)
	aSub1 := new(big.Int).Sub(a, one)
	l = new(big.Int).Div(aSub1, n)
	return
}

//g=n+1
func GetG(n *big.Int) (g *big.Int) {
	g = new(big.Int).Add(n, one)
	//alpha := big.NewInt(int64(prime.RandInt(0, int(n.Int64()))))
	//beta := big.NewInt(int64(prime.RandInt(0, int(n.Int64()))))
	//alphan := new(big.Int).Mul(alpha, n)
	//alphan1 := new(big.Int).Add(alphan, big.NewInt(1))
	//betaN := new(big.Int).Exp(beta, n, nil)
	//ab := new(big.Int).Mul(alphan1, betaN)
	//n2 := new(big.Int).Mul(n, n)
	//g = new(big.Int).Mod(ab, n2)
	return
}

//密钥对生成
func KeyPairGen(bits int) (key Key, err error) {

	var p *big.Int
	var q *big.Int
	for{
		p, err = rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return key, err
		}

		q, err = rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return key, err
		}
		if p.Cmp(q)!=0{
			break
		}
	}


	pq := new(big.Int).Mul(p, q)           //p*q
	pSub1 := new(big.Int).Sub(p, one)      //p-1
	qSub1 := new(big.Int).Sub(q, one)      //q-1
	p1q1 := new(big.Int).Mul(pSub1, qSub1) // (p-1)*(q-1)

	//gcd(pq,(p-1)(q-1))
	gcd := new(big.Int).GCD(nil, nil, pq, p1q1)
	if gcd.Cmp(one) != 0 {
		return key, errors.New("gcd failure")
	}

	n := pq
	lambda := Lcm(pSub1, qSub1)
	nn := new(big.Int).Mul(n, n)
	g := GetG(n)

	gExpLambda := new(big.Int).Exp(g, lambda, nil)
	l := L(new(big.Int).Mod(gExpLambda, nn), n)
	mu := new(big.Int).Mod(new(big.Int).ModInverse(l, n), n)

	//public key (n,g)
	key.PubK.G = g
	key.PubK.N = n

	//privte key (lambda,mu)
	key.PrivK.Lambda = lambda
	key.PrivK.Mu = mu

	return key, nil
}

//加密
func Encrypt(pk *PublicKey, m *big.Int) (c *big.Int, err error) {

	if m.Int64() < int64(0) || m.Int64() >= pk.N.Int64() {
		err = errors.New("m must be an integer greater than or equal to 0 and less than n")
		return
	}

	r, err := rand.Int(rand.Reader, pk.N) // 随机生成一个小于n的整数
	if err != nil {
		return
	}

	//c = g^m * r^n mod n^2
	gExpM := new(big.Int).Exp(pk.G, m, nil)
	rExpN := new(big.Int).Exp(r, pk.N, nil)
	nn := new(big.Int).Mul(pk.N, pk.N)
	c = new(big.Int).Mod(new(big.Int).Mul(gExpM, rExpN), nn)
	return
}

//解密
func Decrypt(pk *PublicKey, sk *PrivKey, c *big.Int) (m *big.Int, err error) {
	cExpLambda := new(big.Int).Exp(c, sk.Lambda, nil)
	mu := sk.Mu
	n := pk.N
	nn := new(big.Int).Mul(pk.N, pk.N)

	m = new(big.Int).Mod(new(big.Int).Mul(L(new(big.Int).Mod(cExpLambda, nn), n), mu), n)
	if m.Int64() < int64(0) || m.Int64() >= pk.N.Int64() {
		err = errors.New("m must be an integer greater than or equal to 0 and less than n")
		return
	}

	return
}
