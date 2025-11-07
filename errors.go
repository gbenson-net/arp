package arp

import "fmt"

const (
	ipAddrKind = "IP address"
	hwAddrKind = "hardware address"
)

type duplicateError struct {
	kind, item string
}

func (e duplicateError) Error() string {
	return fmt.Sprintf("duplicate %s %s", e.kind, e.item)
}

type notFoundError struct {
	kind string
	item fmt.Stringer
}

func (e notFoundError) Error() string {
	return fmt.Sprintf("%s %s not found", e.kind, e.item.String())
}
