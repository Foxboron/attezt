package sqlite

import "github.com/foxboron/attezt/internal/attest"

type Sqlite struct {
	dir string
}

func NewSqlite() *Sqlite {
	return &Sqlite{
		dir: "sqlite.db",
	}
}

func (s *Sqlite) Lookup(attestation *attest.Attestation) (bool, error) {
	return true, nil
}

func (s *Sqlite) Enroll() error {
	return nil
}

func (s *Sqlite) Remove() error {
	return nil
}
