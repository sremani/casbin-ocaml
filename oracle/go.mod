module casbin-ocaml/oracle

go 1.20

require github.com/casbin/casbin/v3 v3.0.0

require (
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/casbin/govaluate v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

replace github.com/casbin/casbin/v3 => ../upstream/casbin
