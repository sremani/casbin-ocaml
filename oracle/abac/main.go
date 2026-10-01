package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	casbin "github.com/casbin/casbin/v3"
)

func fail(err interface{}) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func main() {
	defer func() {
		if value := recover(); value != nil {
			fail(value)
		}
	}()
	if len(os.Args) != 3 {
		fail("usage: casbin-abac-oracle MODEL POLICY")
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	var decoded interface{}
	if err = json.Unmarshal(data, &decoded); err != nil {
		fail(err)
	}
	request, ok := decoded.([]interface{})
	if !ok {
		fail("request must be a JSON array")
	}
	e, err := casbin.NewEnforcer(os.Args[1], os.Args[2])
	if err != nil {
		fail(err)
	}
	// Keep strings opaque; request objects are native JSON maps, not heuristic JSON strings.
	result, err := e.Enforce(request...)
	if err != nil {
		fail(err)
	}
	fmt.Println(result)
}
