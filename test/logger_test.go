package test

import (
	"testing"

	"github.com/hyperledger/burrow/logging"
)

func setupLogger(m *testing.M) {
	nopLogger = logging.NewNoopLogger()
}
