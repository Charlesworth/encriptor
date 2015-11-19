package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
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
	//argInit()

	//encrypt := flag.String("encrypt", "", "encrypt or decrypt")
	inputFile := flag.String("inputFile", "", "file to be acted upon")
	key := flag.String("key", "", "crypto key (must be 32 bytes long)")
	outputFile := flag.String("outputFile", "", "file to be output")
	flag.Parse()

	if encript {
		//encriptFile(filename, keyString, "testencrypt")
		encriptFile(*inputFile, *key, *outputFile)
	} else {
		decriptFile(*inputFile, *key, *outputFile)
	}
}

func encriptFile(inputFileName string, key string, outputFileName string) error {
	inputByte, err := fileToByte(inputFileName)
	if err != nil {
		return err
	}

	keyByte := []byte(key)
	encryptedByte, err := encryptByte(keyByte, inputByte)
	if err != nil {
		return err
	}

	err = byteToFile(encryptedByte, outputFileName)
	return err
}

func decriptFile(fileName string, key string, outputFileName string) error {
	encryptedByte, err := fileToByte(fileName)
	if err != nil {
		return err
	}

	keyByte := []byte(key)
	decryptedByte, err := decryptByte(keyByte, encryptedByte)
	if err != nil {
		log.Fatal(err)
	}

	err = byteToFile(decryptedByte, outputFileName)
	return err
}

func encryptByte(key, text []byte) ([]byte, error) {
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

func decryptByte(key, text []byte) ([]byte, error) {
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

func fileToByte(file string) ([]byte, error) {
	data, err := ioutil.ReadFile(file)
	return data, err
}

func byteToFile(b []byte, file string) error {
	err := ioutil.WriteFile(file, b, 0644)
	return err
}
