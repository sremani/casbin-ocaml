package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	casbin "github.com/casbin/casbin/v3"
)

func fail(err interface{}) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func rows(value [][]string, err error) string {
	if err != nil {
		return "error"
	}
	encoded := make([]string, len(value))
	for i, row := range value {
		fields := make([]string, len(row))
		for j, field := range row {
			fields[j] = hex.EncodeToString([]byte(field))
		}
		encoded[i] = strings.Join(fields, ",")
	}
	return "rows\t" + strings.Join(encoded, ";")
}

func values(value []string, err error) string {
	if err != nil {
		return "error"
	}
	sort.Strings(value)
	encoded := make([]string, len(value))
	for i, field := range value {
		encoded[i] = hex.EncodeToString([]byte(field))
	}
	return "values\t" + strings.Join(encoded, ",")
}

func decision(value bool, err error) string {
	if err != nil {
		return "error"
	}
	return strconv.FormatBool(value)
}

func operation(e *casbin.Enforcer, line string) (result string) {
	result = "error"
	defer func() {
		if recover() != nil {
			result = "error"
		}
	}()
	parts := strings.Split(line, "\t")
	arguments := make([]interface{}, len(parts)-1)
	stringsArgs := make([]string, len(parts)-1)
	for i, part := range parts[1:] {
		decoded, err := hex.DecodeString(part)
		if err != nil {
			return "error"
		}
		stringsArgs[i] = string(decoded)
		arguments[i] = string(decoded)
	}
	switch parts[0] {
	case "enforce":
		return decision(e.Enforce(arguments...))
	case "get_policy":
		if len(arguments) != 0 {
			return "error"
		}
		return rows(e.GetPolicy())
	case "has_policy":
		return decision(e.HasPolicy(arguments...))
	case "add_policy":
		return decision(e.AddPolicy(arguments...))
	case "remove_policy":
		return decision(e.RemovePolicy(arguments...))
	case "get_grouping_policy":
		if len(arguments) != 0 {
			return "error"
		}
		return rows(e.GetGroupingPolicy())
	case "has_grouping_policy":
		return decision(e.HasGroupingPolicy(arguments...))
	case "add_grouping_policy":
		return decision(e.AddGroupingPolicy(arguments...))
	case "remove_grouping_policy":
		return decision(e.RemoveGroupingPolicy(arguments...))
	case "get_roles_for_user":
		if len(arguments) != 1 {
			return "error"
		}
		return values(e.GetRolesForUser(stringsArgs[0]))
	case "get_roles_for_user_in_domain":
		if len(arguments) != 2 {
			return "error"
		}
		return values(e.GetRolesForUser(stringsArgs[0], stringsArgs[1]))
	case "get_users_for_role_in_domain":
		if len(arguments) != 2 {
			return "error"
		}
		return values(e.GetUsersForRole(stringsArgs[0], stringsArgs[1]))
	case "get_users_for_role":
		if len(arguments) != 1 {
			return "error"
		}
		return values(e.GetUsersForRole(stringsArgs[0]))
	}
	return "error"
}

func main() {
	defer func() {
		if value := recover(); value != nil {
			fail(value)
		}
	}()
	if len(os.Args) != 3 {
		fail("usage: casbin-management-oracle MODEL POLICY")
	}
	e, err := casbin.NewEnforcer(os.Args[1], os.Args[2])
	if err != nil {
		fail(err)
	}
	e.EnableAutoSave(false)
	input := bufio.NewReader(os.Stdin)
	for {
		line, err := input.ReadString('\n')
		if err != nil && err != io.EOF {
			fail(err)
		}
		if len(line) != 0 {
			line = strings.TrimSuffix(line, "\n")
			fmt.Println(operation(e, line))
		}
		if err == io.EOF {
			return
		}
	}
}
