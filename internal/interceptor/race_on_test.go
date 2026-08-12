//go:build race

package interceptor

// raceEnabled reports whether the test binary was built with -race.
//
// The race detector instruments every memory access, which costs 5-20x. That
// is the right trade for finding data races and the wrong one for measuring
// latency, so the performance assertion sits this run out.
const raceEnabled = true
