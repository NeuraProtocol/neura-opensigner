package main

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestCryptoShareRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	shareEncryptionKey = key

	plaintext := "sample-ecdsa-private-key-share-12345"
	encrypted, err := encryptShare(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt share: %v", err)
	}

	decrypted, err := decryptShare(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt share: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("expected decrypted %q, got %q", plaintext, decrypted)
	}
}

func TestCryptoInvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	shareEncryptionKey = key

	// Short ciphertext (less than nonce size)
	shortEncoded := hex.EncodeToString([]byte("short"))
	_, err := decryptShare(shortEncoded)
	if err == nil {
		t.Fatalf("expected error decrypting short ciphertext")
	}

	// Corrupted base64
	_, err = decryptShare("!!!not-base-64!!!")
	if err == nil {
		t.Fatalf("expected error for invalid base64")
	}
}
