package main

import (
	"flag"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func seedAccount(store Storage, fname, lname, pw string) *Account {
	acc, err := NewAccount(fname, lname, pw)
	if err != nil {
		log.Fatal(err)
	}

	if err := store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}

	fmt.Println("new account => ", acc.Number)

	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "anthony", "GG", "hunter88888")
}

func main() {
	LoadConfig() // ✅ load env vars at startup
	seed := flag.Bool("seed", false, "seed the db")
	flag.Parse()

	// Load env, init DB, etc...
	InitRedis()

	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	if *seed {
		fmt.Println("seeding the database")
		acc := seedAccount(store, "anthony", "GG", "hunter88888")

		// Check password match
		err := bcrypt.CompareHashAndPassword([]byte(acc.EncryptedPassword), []byte("hunter88888"))
		fmt.Println("Password Valid?", err == nil) // ✅ should print true
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	if *seed {
		fmt.Println("seeding the database")
		seedAccounts(store)
	}

	server := NewAPIServer(":3000", store)
	server.Run()
}
