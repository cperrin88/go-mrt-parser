package test

import (
	"github.com/cperrin88/go-mrt-parser/pkg/mrt"
	"os"
	"testing"
)

func TestParser(t *testing.T) {
	f, _ := os.Open("bird_bgp_master6.mrt")
	parser := &mrt.Parser{File: f}
	parser.Parse()

	if len(parser.Records) == 0 {
		t.Fatal("No Records")
	}

	return
}
