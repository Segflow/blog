package benchmark

import (
	"runtime"
	"testing"
)

func switchImplementation() int {
	switch runtime.GOARCH {
	case "amd64":
		return 0
	case "arm64":
		return 1
	case "arm":
		return 2
	}

	return 0
}

func return0() int {
	return 0
}

func BenchmarkSwitchImpl(b *testing.B) {
	for i := 0; i < b.N; i++ {
		switchImplementation()
	}
}

func mapImplementation() int {
	return map[string]int{
		"amd64": 0,
		"arm":   1,
		"arm64": 2,
	}[runtime.GOARCH]
}

func BenchmarkMapImpl(b *testing.B) {
	for i := 0; i < b.N; i++ {
		mapImplementation()
	}
}
