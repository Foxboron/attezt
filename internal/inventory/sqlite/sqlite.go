package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/foxboron/attezt/internal/attest"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type DeviceData struct {
	EKCert string `json:"ekcert"`
}

const (
	schema = `
		CREATE TABLE IF NOT EXISTS devices (
			ekcert TEXT PRIMARY KEY,
			json_data BLOB
		) STRICT;
	`
)

type Sqlite struct {
	path string
	db   *sqlitex.Pool
}

func NewSqlite() *Sqlite {
	// Default values
	return &Sqlite{
		path: "sqlite.db",
	}
}

func (s *Sqlite) Init(config map[string]any) error {
	if item, ok := config["path"]; ok {
		path, ok := item.(string)
		if !ok {
			return fmt.Errorf("not a valid string for path")
		}
		s.path = path
	}

	dbpool, err := sqlitex.NewPool(s.path, sqlitex.PoolOptions{
		PoolSize: 10,
		PrepareConn: func(conn *sqlite.Conn) error {
			return sqlitex.ExecScript(conn, schema)
		},
	})
	if err != nil {
		return err
	}
	// TODO: Ugly hack
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		dbpool.Close()
	}()
	s.db = dbpool
	return nil
}

func (s *Sqlite) GetEntry(key string) (any, error) {
	conn, err := s.db.Take(context.Background())
	if err != nil {
		return false, err
	}
	defer s.db.Put(conn)

	var jsonData []byte
	if err = sqlitex.Execute(conn, "SELECT json(json_data) FROM devices WHERE ekcert = ?", &sqlitex.ExecOptions{
		Args: []any{key},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			jsonData = make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, jsonData)
			return nil
		},
	}); err != nil {
		return false, err
	}

	if len(jsonData) == 0 {
		return false, nil
	}

	var data DeviceData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return false, err
	}

	return true, nil
}

func (s *Sqlite) Lookup(attestation *attest.Attestation) (bool, error) {
	conn, err := s.db.Take(context.Background())
	if err != nil {
		return false, err
	}
	defer s.db.Put(conn)

	var jsonData []byte
	if err = sqlitex.Execute(conn, "SELECT json(json_data) FROM devices WHERE ekcert = ?", &sqlitex.ExecOptions{
		Args: []any{attestation.EKPubHash()},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			jsonData = make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, jsonData)
			return nil
		},
	}); err != nil {
		return false, err
	}

	if len(jsonData) == 0 {
		return false, nil
	}

	var data DeviceData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return false, err
	}

	return true, nil
}

func (s *Sqlite) Enroll(data map[string]any) error {
	var enroll DeviceData
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, &enroll); err != nil {
		return err
	}
	conn, err := s.db.Take(context.Background())
	if err != nil {
		return err
	}
	defer s.db.Put(conn)

	return sqlitex.Execute(conn, `
		INSERT INTO devices (ekcert, json_data)
		VALUES (?, JSONB(?))
		ON CONFLICT(ekcert) DO UPDATE SET
			json_data = excluded.json_data
	`, &sqlitex.ExecOptions{
		Args: []any{enroll.EKCert, string(jsonData)},
	})
}

func (s *Sqlite) Remove(data map[string]any) error {
	var remove DeviceData
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, &remove); err != nil {
		return err
	}
	conn, err := s.db.Take(context.Background())
	if err != nil {
		return err
	}
	defer s.db.Put(conn)

	return sqlitex.Execute(conn, "DELETE FROM devices WHERE ekcert = ?", &sqlitex.ExecOptions{
		Args: []any{remove.EKCert},
	})
}

func (s *Sqlite) List() (any, error) {
	var data []*DeviceData
	conn, err := s.db.Take(context.Background())
	if err != nil {
		return data, err
	}
	defer s.db.Put(conn)

	var jsonData []byte
	if err = sqlitex.Execute(conn, "SELECT json(json_data) FROM devices", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			var dev DeviceData
			jsonData = make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, jsonData)
			if err := json.Unmarshal(jsonData, &dev); err != nil {
				return err
			}
			data = append(data, &dev)
			return nil
		},
	}); err != nil {
		return data, err
	}
	return data, nil
}
