package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/aybabtme/hmachttp"
)

func main() {
	var (
		keyID      = flag.String("id", "", "id to use for the key")
		privateKey = flag.String("key", "", "key to use for signing")
	)
	flag.Parse()
	if *keyID == "" {
		log.Fatal("missing --id")
	}
	if *privateKey == "" {
		log.Fatal("missing --key")
	}
	header, err := hmachttp.GenerateHeader(*keyID, []byte(*privateKey))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(header)
}
