package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type CBCReader struct {
	key    string
	iv     []byte
	reader io.Reader
	mode   cipher.BlockMode
	eof    bool
}

func (r *CBCReader) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if r.eof {
		return 0, io.EOF
	}
	if len(buf) < aes.BlockSize {
		return 0, errors.New("read buffer is too small")
	}

	if r.mode == nil {
		if len(r.iv) < aes.BlockSize {
			return 0, errors.New("invalid iv size")
		}
		key := sha256.Sum256([]byte(r.key))
		for round := 1; round <= 99; round++ {
			key = sha256.Sum256(key[:])
		}
		iv := sha256.Sum256(append(key[:aes.BlockSize], r.iv[:aes.BlockSize]...))
		for round := 1; round <= 99; round++ {
			iv = sha256.Sum256(iv[:])
		}
		block, err := aes.NewCipher(key[:aes.BlockSize])
		if err != nil {
			return 0, err
		}
		r.mode = cipher.NewCBCDecrypter(block, iv[:aes.BlockSize])
	}

	n, err = io.ReadFull(r.reader, buf[:(len(buf)/aes.BlockSize)*aes.BlockSize])
	if n == 0 {
		return 0, io.EOF
	}
	if n%aes.BlockSize != 0 {
		return 0, errors.New("invalid padding")
	}
	if err != nil {
		r.eof = true
	}
	r.mode.CryptBlocks(buf[:n], buf[:n])
	return
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <key> <backup> [<backup>...]\n", filepath.Base(os.Args[0]))
		return
	}

	for _, backup := range os.Args[2:] {
		prefix := filepath.Base(backup)
		prefix = strings.TrimSuffix(prefix, filepath.Ext(prefix))

		handle, err := os.Open(backup)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
			continue
		}

	done:
		for {
			outer := tar.NewReader(handle)
			header, err := outer.Next()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
				break
			}
			if filepath.Base(header.Name) != "backup.json" || header.Size > 4<<10 {
				fmt.Fprintf(os.Stderr, "%s: invalid backup archive\n\n", backup)
				break
			}
			content, err := io.ReadAll(outer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
				break
			}
			manifest := map[string]any{}
			if err := json.Unmarshal(content, &manifest); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
				break
			}
			protected, compressed := false, false
			if value, ok := manifest["protected"].(bool); ok {
				protected = value
			}
			if value, ok := manifest["compressed"].(bool); ok {
				compressed = value
			}
			content, _ = json.MarshalIndent(manifest, "", "  ")
			fmt.Printf("%s %s\n", prefix, content)

			header, err = outer.Next()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
				break
			}
			if header.Size < 1<<10 || (protected && header.Size%aes.BlockSize != 0) {
				fmt.Fprintf(os.Stderr, "%s: invalid backup archive\n\n", backup)
				break
			}

			reader := bufio.NewReader(outer)
			if protected {
				secure := [48]byte{}
				_, err := io.ReadFull(outer, secure[:])
				if err != nil || !bytes.Equal(secure[:16], []byte("SecureTar\x02\x00\x00\x00\x00\x00\x00")) {
					fmt.Fprintf(os.Stderr, "%s: invalid protected archive\n\n", backup)
					break
				}
				reader = bufio.NewReader(&CBCReader{key: os.Args[1], iv: secure[32:], reader: reader})
			}
			if compressed {
				gzreader, err := gzip.NewReader(reader)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
					break
				}
				reader = bufio.NewReader(gzreader)
			}

			inner := tar.NewReader(reader)
			for {
				header, err := inner.Next()
				if err != nil {
					if err != io.EOF {
						fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
					}
					break
				}
				path := filepath.Join(prefix, strings.TrimPrefix(header.Name, string(filepath.Separator)))
				switch header.Typeflag {
				case tar.TypeReg:
					os.MkdirAll(filepath.Dir(path), 0o755)
					handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
						break done
					}
					_, err = io.Copy(handle, inner)
					handle.Close()
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s: %v\n\n", backup, err)
						break done
					}
					fmt.Printf("%9d %s\n", header.Size, path)

				case tar.TypeDir:
					os.MkdirAll(path, 0o755)

				case tar.TypeSymlink:
					if header.Linkname != "" {
						os.Symlink(header.Linkname, path)
					}
				}
			}
			fmt.Printf("\n")

			break
		}

		handle.Close()
	}
}
