package main

import (
	"fmt"
	"os"

	casbin "github.com/casbin/casbin/v3"
)

func fail(err interface{}) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func main() {
	defer func() {
		if recovered := recover(); recovered != nil {
			fail(recovered)
		}
	}()
	if len(os.Args) < 3 {
		fail("usage: casbin-oracle MODEL POLICY [REQUEST...]")
	}
	enforcer, err := casbin.NewEnforcer(os.Args[1], os.Args[2])
	if err != nil {
		fail(err)
	}
	request := make([]interface{}, len(os.Args)-3)
	for i, value := range os.Args[3:] {
		request[i] = value
	}
	result, err := enforcer.Enforce(request...)
	if err != nil {
		fail(err)
	}
	fmt.Println(result)
}
