/*

   Copyright 2016 Wenhui Shen <www.webx.top>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

package codec

import (
	"crypto/des"
	"encoding/base64"
	"log"
)

func NewDesECBCrypto() *DesECBCrypto {
	return &DesECBCrypto{
		key: make(map[string][]byte),
	}
}

type DesECBCrypto struct {
	key map[string][]byte
}

func (d *DesECBCrypto) Encode(text, secret string) string {
	out := d.EncodeBytes([]byte(text), []byte(secret))
	return base64.StdEncoding.EncodeToString(out)
}

func (d *DesECBCrypto) Decode(crypted, secret string) string {
	data, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		log.Println(err)
		return ``
	}
	out := d.DecodeBytes(data, []byte(secret))
	return string(out)
}

func (d *DesECBCrypto) EncodeBytes(text, secret []byte) []byte {
	data := text
	key := secret
	key = d.GenKey(key)
	block, err := des.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil
	}
	bs := block.BlockSize()
	data = PKCS5Padding(data, bs)
	if len(data)%bs != 0 {
		log.Println("Need a multiple of the blocksize")
		return nil
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return out
}

func (d *DesECBCrypto) DecodeBytes(crypted, secret []byte) []byte {
	defer func() {
		if r := recover(); r != nil {
			log.Println(r)
		}
	}()
	data := crypted
	key := secret
	key = d.GenKey(key)
	block, err := des.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		log.Println("crypto/cipher: input not full blocks")
		return nil
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	out = PKCS5UnPadding(out)
	return out
}

func (d *DesECBCrypto) GenKey(key []byte) []byte {
	if d.key == nil {
		d.key = make(map[string][]byte, 0)
	}
	ckey := string(key)
	kkey, ok := d.key[ckey]
	if !ok {
		d.key[ckey] = DesGenKey(key)
	}
	return kkey
}
