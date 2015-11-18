package main

import (
	"testing"
)

func TestEncriptByte(t *testing.T) {
	inputByte := []byte("This text should be encripted because its full of secret information!")

	invalidTestKey := []byte("this key is too small")
	_, err := encryptByte(invalidTestKey, inputByte)
	if err == nil {
		t.Error("encrypt with a key not of 32 bit size should have returned an error")
	}

	validTestKey := []byte("a 32 bit keyyyyyyyyyyyyyyyyyyyyy")
	encriptedByte, err := encryptByte(validTestKey, inputByte)
	if err != nil {
		t.Error("encrypt failed with error: ", err)
	}
	if string(encriptedByte) == string(inputByte) {
		t.Error("encrypt failed to encrypt the input text")
	}
}

func TestDecriptByte(t *testing.T) {
	inputByte := []byte("This text should be encripted because its full of secret information!")

	invalidTestKey := []byte("this key is too small")
	_, err := decryptByte(invalidTestKey, inputByte)
	if err == nil {
		t.Error("encrypt with a key not of 32 bit size should have returned an error")
	}

	validTestKey := []byte("a 32 bit keyyyyyyyyyyyyyyyyyyyyy")
	testString := "hello, is it me your looking for?"
	encriptedByte, _ := encryptByte(validTestKey, []byte(testString))
	decriptedByte, err := decryptByte(validTestKey, encriptedByte)
	if err != nil {
		t.Error("decrypt failed with error: ", err)
	}
	if string(decriptedByte) != testString {
		t.Error("decriptedByte: [", string(decriptedByte), "] did not match testString: [", testString, "]")
	}
}
