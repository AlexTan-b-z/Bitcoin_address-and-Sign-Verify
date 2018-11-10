package key

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

const (
	version            = byte(0x00)
	addreddChechsumLen = 4
	privKeyBytesLen    = 32
)

type GKey struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
}

func (k GKey) GetPrivKey() []byte {
	d := k.privateKey.D.Bytes()
	b := make([]byte, 0, privKeyBytesLen)
	priKey := paddedAppend(privKeyBytesLen, b, d) // []bytes type
	// s := byteToString(priKey)
	return priKey
}

func (k GKey) GetPubKey() []byte {
	pubKey := append(k.PublicKey.X.Bytes(), k.privateKey.Y.Bytes()...) // []bytes type
	// s := byteToString(pubKey)
	return pubKey
}

/*
对text签名
返回加密结果，结果为数字证书r、s的序列化后拼接，然后用hex转换为string
*/
func (k GKey) Sign(text []byte) (string, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.privateKey, text)
	if err != nil {
		return "", err
	}
	rt, err := r.MarshalText()
	if err != nil {
		return "", err
	}
	st, err := s.MarshalText()
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	defer w.Close()
	_, err = w.Write([]byte(string(rt) + "+" + string(st)))
	if err != nil {
		return "", err
	}
	w.Flush()
	return hex.EncodeToString(b.Bytes()), nil
}

// 得到地址
func (k GKey) GetAddress() (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */
	pub_bytes := k.GetPubKey()

	/* SHA256 HASH */
	fmt.Println("1 - Perform SHA-256 hashing on the public key")
	sha256_h := sha256.New()
	sha256_h.Reset()
	sha256_h.Write(pub_bytes)
	pub_hash_1 := sha256_h.Sum(nil) // 对公钥进行hash256运算
	fmt.Println(ByteToString(pub_hash_1))
	fmt.Println("================")

	/* RIPEMD-160 HASH */
	fmt.Println("2 - Perform RIPEMD-160 hashing on the result of SHA-256")
	ripemd160_h := ripemd160.New()
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil) // 对公钥hash进行ripemd160运算
	fmt.Println(ByteToString(pub_hash_2))
	fmt.Println("================")
	/* Convert hash bytes to base58 chech encoded sequence */
	address = b58checkencode(0x00, pub_hash_2)

	return address
}

/*
证书分解
通过hex解码，分割成数字证书r，s
*/
func getSign(signature string) (rint, sint big.Int, err error) {
	byterun, err := hex.DecodeString(signature)
	if err != nil {
		err = errors.New("decrypt error," + err.Error())
		return
	}
	r, err := gzip.NewReader(bytes.NewBuffer(byterun))
	if err != nil {
		err = errors.New("decode error," + err.Error())
		return
	}
	defer r.Close()
	buf := make([]byte, 1024)
	count, err := r.Read(buf)
	if err != nil {
		fmt.Println("decode = ", err)
		err = errors.New("decode read error," + err.Error())
		return
	}
	rs := strings.Split(string(buf[:count]), "+")
	if len(rs) != 2 {
		err = errors.New("decode fail")
		return
	}
	err = rint.UnmarshalText([]byte(rs[0]))
	if err != nil {
		err = errors.New("decrypt rint fail, " + err.Error())
		return
	}
	err = sint.UnmarshalText([]byte(rs[1]))
	if err != nil {
		err = errors.New("decrypt sint fail, " + err.Error())
		return
	}
	return
}

/*
校验文本内容是否与签名一致
使用公钥校验签名和文本内容
*/
func Verify(text []byte, signature string, pubKey *ecdsa.PublicKey) (bool, error) {
	rint, sint, err := getSign(signature)
	if err != nil {
		return false, err
	}
	result := ecdsa.Verify(pubKey, text, &rint, &sint)
	return result, nil
}

// 生成密钥对
func MakeNewKey(randKey string) (*GKey, error) {
	var err error
	var gkey GKey
	var curve elliptic.Curve // 椭圆曲线参数

	lenth := len(randKey)
	if lenth < 224/8+8 {
		err = errors.New("RandKey is too short. It mast be longer than 36 bytes.")
		return &gkey, err
	} else if lenth > 521/8+8 {
		curve = elliptic.P521()
	} else if lenth > 384/8+8 {
		curve = elliptic.P384()
	} else if lenth > 256/8+8 {
		curve = elliptic.P256()
	} else if lenth > 224/8+8 {
		curve = elliptic.P224()
	}

	private, err := ecdsa.GenerateKey(curve, strings.NewReader(randKey))
	if err != nil {
		log.Panic(err)
	}
	gkey = GKey{private, private.PublicKey}
	return &gkey, nil
}
