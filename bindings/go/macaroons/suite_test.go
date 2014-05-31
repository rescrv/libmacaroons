package macaroons

import (
	"testing"

	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type Suite struct{}

var _ = gc.Suite(&Suite{})
