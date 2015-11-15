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
)

func main() {
	key := []byte("a very very very very secret key") // 32 bytes
	// plaintext := []byte("test text to be ciphered and deciphered")
	plaintext := fileToByte("testFile")
	fmt.Printf("%s\n", plaintext)
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%0x\n", ciphertext)
	byteToFile(ciphertext, "testFile.scrammbled")
	result, err := decrypt(key, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", result)
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
		log.Fatal("unable to open file", file, "with error:", err)
	}
	return dat
}

func byteToFile(b []byte, file string) {
	err := ioutil.WriteFile(file, b, 0644)
	if err != nil {
		log.Fatal("unable to save file", file, "with error:", err)
	}
}

// func main() {
//
//     // Perhaps the most basic file reading task is
//     // slurping a file's entire contents into memory.
//
//     // You'll often want more control over how and what
//     // parts of a file are read. For these tasks, start
//     // by `Open`ing a file to obtain an `os.File` value.
//     f, err := os.Open("/tmp/dat")
//     check(err)
//
//     // Read some bytes from the beginning of the file.
//     // Allow up to 5 to be read but also note how many
//     // actually were read.
//     b1 := make([]byte, 5)
//     n1, err := f.Read(b1)
//     check(err)
//     fmt.Printf("%d bytes: %s\n", n1, string(b1))
//
//     // You can also `Seek` to a known location in the file
//     // and `Read` from there.
//     o2, err := f.Seek(6, 0)
//     check(err)
//     b2 := make([]byte, 2)
//     n2, err := f.Read(b2)
//     check(err)
//     fmt.Printf("%d bytes @ %d: %s\n", n2, o2, string(b2))
//
//     // The `io` package provides some functions that may
//     // be helpful for file reading. For example, reads
//     // like the ones above can be more robustly
//     // implemented with `ReadAtLeast`.
//     o3, err := f.Seek(6, 0)
//     check(err)
//     b3 := make([]byte, 2)
//     n3, err := io.ReadAtLeast(f, b3, 2)
//     check(err)
//     fmt.Printf("%d bytes @ %d: %s\n", n3, o3, string(b3))
//
//     // There is no built-in rewind, but `Seek(0, 0)`
//     // accomplishes this.
//     _, err = f.Seek(0, 0)
//     check(err)
//
//     // The `bufio` package implements a buffered
//     // reader that may be useful both for its efficiency
//     // with many small reads and because of the additional
//     // reading methods it provides.
//     r4 := bufio.NewReader(f)
//     b4, err := r4.Peek(5)
//     check(err)
//     fmt.Printf("5 bytes: %s\n", string(b4))
//
//     // Close the file when you're done (usually this would
//     // be scheduled immediately after `Open`ing with
//     // `defer`).
//     f.Close()
//
// }
