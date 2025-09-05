package faroe

import "time"

type ClockInterface interface {
	// Returns the current time.
	Now() time.Time
}

// Implements [ClockInterface].
// Uses the current system time.
var RealClock = realClockStruct{}

type realClockStruct struct{}

func (realClockStruct) Now() time.Time {
	return time.Now()
}
