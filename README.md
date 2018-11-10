# go实现椭圆曲线加解密、签名验证算法（go ecdsa库的运用），及生成比特币地址过程讲解、BASE58实现

*作者: AlexTan* 
*CSDN:   http://blog.csdn.net/alextan_*  
*Github: https://github.com/AlexTan-b-z*  
*e-mail: alextanbz@gmail.com*



## 前言

- 椭圆曲线原理参考(讲解得很易懂): http://blog.51cto.com/11821908/2057726 
- ecdsa中文文档：https://studygolang.com/pkgdoc

- 本文主要讲解使用Go的ecdsa库实现椭圆曲线加解密、签名、验证算法，同时通过公钥生成比特币地址，具体代码逻辑参考bitcoin0.1的key.h、base58.h。



- [原文博客地址]()：

- 喜欢可以Star支持一下哦！



## 生成密钥对



```go
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
```

解释：randKey可以是随机的，也可以是用户输入的助记词，randKey决定私钥，当然同时也决定了公钥。



## 公钥转换为比特币地址

#### 具体逻辑实现逻辑是：

 1. 先对pubKey进行sha256运算

 2. 再对1步骤得到的值进行ripemed160运算

 3. 再对2得到的值在首部加上2个字节的版本号

 4. 再对3得到的值进行sha256运算

 5. 再对4得到的值进行sha256运算

 6. 把5得到的值的前4个字节加到3得到的值(加上版本号的值)的末尾

 7. 把6得到的值进行base58运算

 8. 如果6得到的值中有出现0，则在7得到的值前加入一个"1"

 9. 得到地址


#### 代码实现：

```go
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

func b58checkencode(ver uint8, b []byte) (s string) {
	/* Prepend version */
	fmt.Println("3 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)")
	bcpy := append([]byte{ver}, b...)
	fmt.Println(ByteToString(bcpy))
	fmt.Println("================")

	/* Create a new SHA256 context */
	sha256H := sha256.New()

	/* SHA256 HASH #1 */
	fmt.Println("4 - Perform SHA-256 hash on the extended PIPEMD-160 result")
	sha256H.Reset()
	sha256H.Write(bcpy)
	hash1 := sha256H.Sum(nil)
	fmt.Println(ByteToString(hash1))
	fmt.Println("================")

	/* SHA256 HASH #2 */
	fmt.Println("5 - Perform SHA-256 hash on the result of the previous SHA-256 hash")
	sha256H.Reset()
	sha256H.Write(hash1)
	hash2 := sha256H.Sum(nil)
	fmt.Println(ByteToString(hash2))
	fmt.Println("================")

	/* Append first four bytes of hash */
	fmt.Println("6 - Take the first 4 bytes of the second SHA-256 hash. This is the address chechsum")
	fmt.Println(ByteToString(hash2[0:4]))
	fmt.Println("================")

	fmt.Println("7 - Add the 4 checksum bytes from stage 7 at the end of extended PIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.")
	bcpy = append(bcpy, hash2[0:4]...)
	fmt.Println(ByteToString(bcpy))
	fmt.Println("================")

	/* Encode base58 string */
	s = b58encode(bcpy)

	/* For number  of leading 0's in bytes, prepend 1 */
	for _, v := range bcpy {
		if v != 0 {
			break
		}
		s = "1" + s
	}
	fmt.Println("8 - Convet the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format")
	fmt.Println(s)
	fmt.Println("================")

	return s
}
```

#### base58实现

```go
func b58encode(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */
	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	x := new(big.Int).SetBytes(b)
	// Initialize
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x /58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}
	return s
}
```



## 数字签名

```go
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
```



## 验证签名

```go
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
```



## 运行结果

```shell
$ go run test.go 
My privateKey is : 00000000323132324153720678C83DFE6126497EF4A8C75CBC9862EEEC77F006
My publickKey is : EF855DD23C7E3462DCA1935EA516573CF44E8C226EC31146D380A9BCC053CE277222BD827B18187152197F5F36B3002812A636615498E40E
1 - Perform SHA-256 hashing on the public key
0EF6B0BCBB3A0434A08EB0190CF5DEE38CF62866BC1F51D9F8EAB71AAC0C0A80
================
2 - Perform RIPEMD-160 hashing on the result of SHA-256
368FE10638FB2890B9C7BC334035F656F0B450FA
================
3 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
00368FE10638FB2890B9C7BC334035F656F0B450FA
================
4 - Perform SHA-256 hash on the extended PIPEMD-160 result
569F0D58CAB5195D5C84ABBA2FFA3883CC93A2C19BF60FF54E5E7E5565251FA2
================
5 - Perform SHA-256 hash on the result of the previous SHA-256 hash
8FEB0E8C808D61D40EC8D9CC17CAB2C12FE1FE841582AEE024A7F6839596CD45
================
6 - Take the first 4 bytes of the second SHA-256 hash. This is the address chechsum
8FEB0E8C
================
7 - Add the 4 checksum bytes from stage 7 at the end of extended PIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
00368FE10638FB2890B9C7BC334035F656F0B450FA8FEB0E8C
================
8 - Convet the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
15yVrFLFoKvh5H5pjUuwF2CpSD4b2rwRqm
================
My address is: 15yVrFLFoKvh5H5pjUuwF2CpSD4b2rwRqm
Signature is : 1f8b08000000000000ff04c0c101c0500c01d0817a49888ffd17eb7b4dd18874c185472e94db29bd0c549cde598a07e008c4001b8a97dea7c2c3971adcc9dd3a48ccb16e1cc37a150727d502e36773fb467d3eec0f0000ffff
Verify success
```
