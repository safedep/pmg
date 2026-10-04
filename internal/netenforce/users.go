package netenforce

import (
	"fmt"
	"os/user"
	"strconv"
)

// resolveUIDs accepts user names and numeric uids. It runs on every
// platform, so the preflight of a daemon parent can report an unknown user
// before it detaches.
func resolveUIDs(users []string) ([]uint32, error) {
	uids := make([]uint32, 0, len(users))
	for _, name := range users {
		if n, err := strconv.ParseUint(name, 10, 32); err == nil {
			uids = append(uids, uint32(n))
			continue
		}
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("enforce: resolve user %q: %w", name, err)
		}
		n, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("enforce: user %q has uid %q: %w", name, u.Uid, err)
		}
		uids = append(uids, uint32(n))
	}
	return uids, nil
}
