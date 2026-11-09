//go:build race

package cloudpolicy

// raceEnabled is true under the race detector, which makes the load many
// times slower.
const raceEnabled = true
