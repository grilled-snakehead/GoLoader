package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// AES-256 encryption key (32 bytes)
var key = []byte("thisis32byteslongpassphraseimusing")

// Encrypts shellcode using AES-256
func encryptShellcode(shellcode []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(shellcode))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], shellcode)

    return ciphertext, nil
}

func main() {
    // Read shellcode from file
    shellcode, err := os.ReadFile("shellcode.bin")
    if err != nil {
        fmt.Println("Error reading shellcode file:", err)
        return
    }

    // Encrypt the shellcode
    encryptedShellcode, err := encryptShellcode(shellcode, key)
    if err != nil {
        fmt.Println("Encryption error:", err)
        return
    }

    // Write encrypted shellcode to file
    err = os.WriteFile("shellcode.enc", encryptedShellcode, 0644)
    if err != nil {
        fmt.Println("Error writing encrypted shellcode to file:", err)
        return
    }

    fmt.Println("Shellcode encrypted and saved to shellcode.enc")
}
