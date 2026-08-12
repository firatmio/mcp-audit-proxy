//go:build !race

package interceptor

// raceEnabled reports whether the test binary was built with -race.
const raceEnabled = false
