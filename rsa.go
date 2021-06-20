package codec

import (
	"bytes"
	"crypto/rsa"
	"io/ioutil"
)

func NewRSA() *RSA {
	return &RSA{}
}

type RSA struct {
	publicKey  *RSAPublicKey
	privateKey *RSAPrivateKey
}

func (r *RSA) SetPublicKey(pubKey string) (err error) {
	r.publicKey, err = NewRSAPublicKey(pubKey)
	return err
}

func (r *RSA) PublicKey() *RSAPublicKey {
	return r.publicKey
}

func (r *RSA) SetPrivateKey(privKey string) (err error) {
	r.privateKey, err = NewRSAPrivateKey(privKey)
	return err
}

func (r *RSA) PrivateKey() *RSAPrivateKey {
	return r.privateKey
}

type RSAPublicKey struct {
	pubStr string         //公钥字符串
	pubkey *rsa.PublicKey //公钥
}

type RSAPrivateKey struct {
	priStr string          //私钥字符串
	prikey *rsa.PrivateKey //私钥
}

// 设置公钥
func NewRSAPublicKey(pubStr string) (r *RSAPublicKey, err error) {
	r = &RSAPublicKey{}
	r.pubStr = pubStr
	r.pubkey, err = r.GetPublickey()
	return
}

// 设置私钥
func NewRSAPrivateKey(priStr string) (r *RSAPrivateKey, err error) {
	r = &RSAPrivateKey{}
	r.priStr = priStr
	r.prikey, err = r.GetPrivatekey()
	return
}

// *rsa.PublicKey
func (r *RSAPrivateKey) GetPrivatekey() (*rsa.PrivateKey, error) {
	return getPriKey([]byte(r.priStr))
}

// *rsa.PrivateKey
func (r *RSAPublicKey) GetPublickey() (*rsa.PublicKey, error) {
	return getPubKey([]byte(r.pubStr))
}

// 公钥加密
func (r *RSAPublicKey) Encrypt(input []byte) ([]byte, error) {
	if r.pubkey == nil {
		return nil, ErrPublicKeyNotSet
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(r.pubkey, bytes.NewReader(input), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// 公钥解密
func (r *RSAPublicKey) Decrypt(input []byte) ([]byte, error) {
	if r.pubkey == nil {
		return nil, ErrPublicKeyNotSet
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(r.pubkey, bytes.NewReader(input), output, false)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// 私钥加密
func (rsas *RSAPrivateKey) Encrypt(input []byte) ([]byte, error) {
	if rsas.prikey == nil {
		return nil, ErrPrivateKeyNotSet
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(input), output, true)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(output)
}

// 私钥解密
func (r *RSAPrivateKey) Decrypt(input []byte) ([]byte, error) {
	if r.prikey == nil {
		return nil, ErrPrivateKeyNotSet
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(r.prikey, bytes.NewReader(input), output, false)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(output)
}
