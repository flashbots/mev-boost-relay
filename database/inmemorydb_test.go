package database

import "testing"

func TestInmemoryDB(t *testing.T) {
	t.Setenv("USE_LOCAL_DB", "1")

	TestSaveValidatorRegistration(t)
}
