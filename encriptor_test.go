package main

import (
	"testing"
)

func TestEncript(t *testing.T) {
	inputByte := []byte("This text should be encripted because its full of secret information!")

	invalidTestKey := []byte("this key is too small")
	_, err := encrypt(invalidTestKey, inputByte)
	if err == nil {
		t.Error("encrypt with a key not of 32 bit size should have returned an error")
	}

	validTestKey := []byte("a 32 bit keyyyyyyyyyyyyyyyyyyyyy")
	encriptedByte, err := encrypt(validTestKey, inputByte)
	if err != nil {
		t.Error("encrypt failed with error: ", err)
	}
	if string(encriptedByte) == string(inputByte) {
		t.Error("encrypt failed to encrypt the input text")
	}
}

func TestDecript(t *testing.T) {
	inputByte := []byte("This text should be encripted because its full of secret information!")

	invalidTestKey := []byte("this key is too small")
	_, err := decrypt(invalidTestKey, inputByte)
	if err == nil {
		t.Error("encrypt with a key not of 32 bit size should have returned an error")
	}

	validTestKey := []byte("a 32 bit keyyyyyyyyyyyyyyyyyyyyy")
	testString := "hello, is it me your looking for?"
	encriptedByte, _ := encrypt(validTestKey, []byte(testString))
	decriptedByte, err := decrypt(validTestKey, encriptedByte)
	if err != nil {
		t.Error("decrypt failed with error: ", err)
	}
	if string(decriptedByte) != testString {
		t.Error("decriptedByte: [", string(decriptedByte), "] did not match testString: [", testString, "]")
	}
}
