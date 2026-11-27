package server

import (
	"errors"
	"testing"
)

func TestIPv6Unavailable(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", want: false},
		{name: "unsupported address family", err: errors.New("listen tcp: address family not supported by protocol"), want: true},
		{name: "unsupported protocol", err: errors.New("listen tcp: protocol not supported"), want: true},
		{name: "address in use", err: errors.New("listen tcp: address already in use"), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ipv6Unavailable(test.err); got != test.want {
				t.Fatalf("ipv6Unavailable(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}
