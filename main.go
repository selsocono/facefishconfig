package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	ct "github.com/daviddengcn/go-colortext"
	"github.com/hillu/go-yara/v4"
	"golang.org/x/crypto/blowfish"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func main() {
	dir := flag.String("dir", "", `path to scan file or directory. example: C:\Windows\System32\`)
	rules := flag.String("rules", "rules.yar", `path to file with rules. example: C:\test1.yar`)
	flag.Parse()

	file, err := ioutil.ReadFile(*rules)
	if err != nil {
		log.Println(err)
		return
	}

	c, err := yara.NewCompiler()
	if c == nil || err != nil {
		log.Println(err)
		return
	}

	if err = c.AddString(string(file), ""); err != nil {
		log.Println(err)
		return
	}

	r, err := c.GetRules()
	if err != nil {
		log.Println(err)
		return
	}

	err = filepath.Walk(*dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println(err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			//log.Println(err)
			return nil
		}

		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Println(err)
			}
		}(file)

		var matches yara.MatchRules

		err = r.ScanFileDescriptor(file.Fd(), 0, 0, &matches)
		if err != nil {
			log.Println(err)
		}

		if len(matches) < 0 {
			return nil
		}

		var ffRootkit, ffDropper, ffConfig bool
		var ffConfigOffset uint64

		_, err = file.Seek(0, 0)
		if err != nil {
			return err
		}

		for _, match := range matches {
			if match.Rule == "FaceFish_Rootkit" {
				ffRootkit = true
			}
			if match.Rule == "FaceFish_Config" {
				ffConfigOffset = match.Strings[0].Offset
				ffConfig = true
			}
			if match.Rule == "FaceFish_UPX_overlay_trick" {
				ffDropper = true
			}
		}

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(file)
		if err != nil {
			return err
		}

		_, err = file.Seek(0, 0)
		if err != nil {
			return err
		}

		SHA256 := sha256.New()

		pagesize := os.Getpagesize()
		reader := bufio.NewReaderSize(file, pagesize)
		multiWriter := io.MultiWriter(SHA256)

		_, err = io.Copy(multiWriter, reader)
		if err != nil {
			log.Println(err)
		}

		if ffRootkit && ffConfig {
			ct.Foreground(ct.Yellow, true)
			fmt.Printf("FaceFish Rootkit: %s, %d, %s\n", file.Name(), info.Size(), hex.EncodeToString(SHA256.Sum(nil)))
			ct.ResetColor()
			fmt.Println(hex.Dump(blowfishDecrypt(buf.Bytes()[ffConfigOffset-128:ffConfigOffset],
				buf.Bytes()[ffConfigOffset-144:ffConfigOffset-128])))
		}

		if ffDropper {
			ct.Foreground(ct.Red, true)
			fmt.Printf("FaceFish Dropper: %s, %d, %s\n", file.Name(), info.Size(), hex.EncodeToString(SHA256.Sum(nil)))
			ct.ResetColor()
			fmt.Println(hex.Dump(blowfishDecrypt(buf.Bytes()[len(buf.Bytes())-128:], []byte("buil"))))
		}
		return nil
	})
}

func blowfishDecrypt(et, key []byte) []byte {
	dcipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	div := et[:blowfish.BlockSize]
	decrypted := et[blowfish.BlockSize:]
	if len(decrypted)%blowfish.BlockSize != 0 {
		panic("decrypted is not a multiple of blowfish.BlockSize")
	}
	dcbc := cipher.NewCBCDecrypter(dcipher, div)
	dcbc.CryptBlocks(decrypted, decrypted)
	return decrypted
}
