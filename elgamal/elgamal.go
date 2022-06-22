package elgamal

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

/*
https://en.wikipedia.org/wiki/ElGamal_encryption

1024-bit MODP Group with 160-bit Prime Order Subgroup
 The hexadecimal value of the prime is:
 p = B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
 DF1FB2BC 2E4A4371
 The hexadecimal value of the generator is:
 g = A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
 D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
 D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
 855E6EEB 22B3B2E5
 The generator generates a prime-order subgroup of size:
 q = F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353
*/

const (

	// The hexadecimal value of the prime is
	primeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E2" +
		"8675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C21" +
		"9A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

	//The hexadecimal value of the generator is
	generatorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266" +
		"FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263" +
		"F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

	//The generator generates a prime-order subgroup of size
	qHex = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353"

	//oneHex = "1"
)

// public key
type PublicKey struct {
	P *big.Int
	G *big.Int
	H *big.Int
}

// private key
type PrivateKey struct {
	PublicKey
	X *big.Int
}

type CipherText struct {
	C1, C2 *big.Int
}

// Convert hex strings to bigInt
func fromHex(in string) (out *big.Int, ok bool) {

	out, ok = new(big.Int).SetString(in, 16)
	if !ok {
		panic("Conversion failure")
	}

	return
}

// GenRandom Sample a uniform random value in [0, q)
func GenRandom() (rd *big.Int) {

	q, _ := fromHex(qHex)
	rd, err := rand.Int(rand.Reader, q)
	if err != nil {
		panic("GenRandom failure")
	}

	return
}

func GenPrivateKey(rd *big.Int) (sk *PrivateKey) {

	g, _ := fromHex(generatorHex)
	p, _ := fromHex(primeHex)
	pk := &PublicKey{
		P: p,
		G: g,
		H: nil,
	}

	sk = &PrivateKey{
		PublicKey: *pk,
		X:         rd,
	}

	return
}

func GenPublickey(sk *PrivateKey) (pk *PublicKey) {

	g, _ := fromHex(generatorHex)
	p, _ := fromHex(primeHex)

	//y = g^x mod p
	h := new(big.Int).Exp(g, sk.X, p)

	pk = &PublicKey{
		P: p,
		G: g,
		H: h,
	}
	return
}

func (pk *PublicKey) Encrypt(m *big.Int) (c *CipherText) {

	y := GenRandom()                      //sample a random y from [0,q)
	s := new(big.Int).Exp(pk.H, y, pk.P)  // s = h^y mod p
	c1 := new(big.Int).Exp(pk.G, y, pk.P) // c1 = g^y
	c2 := new(big.Int).Mul(m, s)          // c2 = m * s

	c = &CipherText{
		C1: c1,
		C2: c2,
	}

	return
}

func (sk *PrivateKey) Decrypt(c *CipherText) (m *big.Int) {

	//fmt.Println("sk.PublicKey.P", sk.PublicKey.P)
	s := new(big.Int).Exp(c.C1, sk.X, sk.PublicKey.P)
	sInverse := new(big.Int).ModInverse(s, sk.PublicKey.P)
	m = new(big.Int).Mod(new(big.Int).Mul(c.C2, sInverse), sk.PublicKey.P)

	return
}
