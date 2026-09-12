//go:build unix

package platform

import "errors"

func parentProcessName() (string, error) { return "", errors.ErrUnsupported }
