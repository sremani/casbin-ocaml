package main

import (
	"fmt"
	casbin "github.com/casbin/casbin/v3"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"time"
)

func fail(err interface{}) { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
func yes(b bool) int {
	if b {
		return 1
	}
	return 0
}
func main() {
	defer func() {
		if r := recover(); r != nil {
			fail(r)
		}
	}()
	if len(os.Args) != 5 {
		fail("usage: benchmark SCENARIO MODEL POLICY ITERATIONS")
	}
	scenario, model, policy := os.Args[1], os.Args[2], os.Args[3]
	iterations, err := strconv.Atoi(os.Args[4])
	if err != nil || iterations <= 0 {
		fail("iterations must be positive")
	}
	enforcer, err := casbin.NewEnforcer(model, policy)
	if err != nil {
		fail(err)
	}
	enforcer.EnableAutoSave(false)
	initial, err := enforcer.GetPolicy()
	if err != nil {
		fail(err)
	}
	baseline := make([][]string, len(initial))
	for i, row := range initial {
		baseline[i] = append([]string(nil), row...)
	}
	var step func() int
	switch scenario {
	case "load":
		step = func() int {
			e, err := casbin.NewEnforcer(model, policy)
			if err != nil {
				fail(err)
			}
			rows, err := e.GetPolicy()
			if err != nil {
				fail(err)
			}
			return len(rows)
		}
	case "management":
		step = func() int {
			added, err := enforcer.AddPolicy("temporary", "data", "read")
			if err != nil {
				fail(err)
			}
			removed, err := enforcer.RemovePolicy("temporary", "data", "read")
			if err != nil {
				fail(err)
			}
			return yes(added) + yes(removed)
		}
	default:
		var request []interface{}
		switch scenario {
		case "acl-first":
			request = []interface{}{"u0", "data", "read"}
		case "acl-last", "priority":
			request = []interface{}{"u99", "data", "read"}
		case "acl-miss":
			request = []interface{}{"absent", "data", "read"}
		case "rbac":
			request = []interface{}{"u0", "data", "read"}
		case "domain":
			request = []interface{}{"u0", "tenant", "data", "read"}
		case "abac":
			request = []interface{}{"alice", map[string]interface{}{"Owner": "alice", "Age": float64(42)}, "read"}
		default:
			fail("unknown scenario")
		}
		step = func() int {
			value, err := enforcer.Enforce(request...)
			if err != nil {
				fail(err)
			}
			return yes(value)
		}
	}
	for i := 0; i < 100; i++ {
		step()
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	checksum := 0
	for i := 0; i < iterations; i++ {
		checksum += step()
	}
	elapsed := time.Since(started).Seconds()
	runtime.ReadMemStats(&after)
	if scenario == "management" {
		rows, err := enforcer.GetPolicy()
		if err != nil || !reflect.DeepEqual(rows, baseline) {
			fail("management state drift")
		}
	}
	fmt.Printf("%s\t%d\t%.9f\t%d\t%d\n", scenario, iterations, elapsed, checksum, after.TotalAlloc-before.TotalAlloc)
}
