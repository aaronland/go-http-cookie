package main

import (
	"flag"
	"fmt"
	"github.com/aaronland/go-http-cookie"
	"log"
)

func main() {

	name := flag.String("name", "c", "...")

	flag.Parse()

	cookie_uri, err := cookie.NewRandomEncryptedCookieURI(*name)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cookie_uri)
}
