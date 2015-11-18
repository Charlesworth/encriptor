package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var encript bool
var filename string
var keyString string

func argInit() {
	if len(os.Args) != 4 {
		log.Fatal("incorrect input Args used, use 'encriptor -h' for instructions")
	}
	if os.Args[1] == "encript" {
		encript = true
	} else if os.Args[1] == "decript" {
		encript = false
	} else {
		log.Fatal("incorrect input Args used, use 'encriptor -h' for instructions")
	}

	filename = os.Args[2]
	keyString = os.Args[3]
}

func main() {
	argInit()
	key := []byte(keyString) // 32 bytes
	// plaintext := []byte("test text to be ciphered and deciphered")
	if encript {
		plaintext := fileToByte(filename)
		fmt.Printf("%s\n", plaintext)
		ciphertext, err := encrypt(key, plaintext)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%0x\n", ciphertext)
		byteToFile(ciphertext, filename+".enc")
	} else {
		ciphertext := fileToByte(filename)
		result, err := decrypt(key, ciphertext)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", result)
		byteToFile(result, "hi")
	}
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func fileToByte(file string) []byte {
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal("unable to open file ", file, " with error: ", err)
	}
	return dat
}

func byteToFile(b []byte, file string) {
	err := ioutil.WriteFile(file, b, 0644)
	if err != nil {
		log.Fatal("unable to save file ", file, " with error: ", err)
	}
}
