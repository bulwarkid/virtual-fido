//go:build !linux

package virtual_fido

import (
	"context"
	"errors"
)

// StartUHID is only available on Linux.
func StartUHID(ctx context.Context, client FIDOClient, name string) error {
	return errors.New("StartUHID is only supported on Linux")
}
