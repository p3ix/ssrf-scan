package db

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Interaction represents a single OOB callback event.
type Interaction struct {
	ID          int64     `json:"id"`
	UUID        string    `json:"uuid"`
	Type        string    `json:"type"` // dns, http, smtp, ldap, redis, mysql, …
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	QueryName   string    `json:"query_name,omitempty"`
	QueryType   string    `json:"query_type,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	Headers     string    `json:"headers,omitempty"` // JSON blob
	Body        string    `json:"body,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	RawData     string    `json:"raw_data,omitempty"`
	DecodedData string    `json:"decoded_data,omitempty"`
}

// RebindConfig holds DNS rebinding configuration for a specific UUID.
type RebindConfig struct {
	UUID         string     `json:"uuid"`
	PublicIP     string     `json:"public_ip"`
	PrivateIP    string     `json:"private_ip"`
	RequestCount int        `json:"request_count"`
	SwitchAfter  int        `json:"switch_after"`
	SwitchAtTime *time.Time `json:"switch_at_time,omitempty"` // time-based mode
}

// Stats aggregates interaction counts by type.
type Stats struct {
	ByType      map[string]int `json:"by_type"`
	Total       int            `json:"total"`
	UniqueUUIDs int            `json:"unique_uuids"`
}

// DB wraps an *sql.DB with domain-specific query methods.
type DB struct {
	*sql.DB
}

// Open initialises the SQLite database, creates tables if needed, and enables WAL mode.
func Open(path string) (*DB, error) {
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	raw.SetMaxOpenConns(1) // SQLite: single writer is safest

	if _, err = raw.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"); err != nil {
		return nil, err
	}

	if err = migrate(raw); err != nil {
		return nil, err
	}

	return &DB{raw}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS interactions (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid         TEXT    NOT NULL DEFAULT '',
			type         TEXT    NOT NULL,
			timestamp    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			source_ip    TEXT,
			query_name   TEXT,
			query_type   TEXT,
			method       TEXT,
			path         TEXT,
			headers      TEXT,
			body         TEXT,
			user_agent   TEXT,
			raw_data     TEXT,
			decoded_data TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_i_uuid      ON interactions(uuid);
		CREATE INDEX IF NOT EXISTS idx_i_type      ON interactions(type);
		CREATE INDEX IF NOT EXISTS idx_i_timestamp ON interactions(timestamp DESC);

		CREATE TABLE IF NOT EXISTS rebind_configs (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid           TEXT    UNIQUE NOT NULL,
			public_ip      TEXT    NOT NULL,
			private_ip     TEXT    NOT NULL,
			request_count  INTEGER NOT NULL DEFAULT 0,
			switch_after   INTEGER NOT NULL DEFAULT 1,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS api_keys (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			key_value   TEXT    UNIQUE NOT NULL,
			description TEXT,
			active      INTEGER NOT NULL DEFAULT 1,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return err
	}

	// Idempotent: add switch_at_time column to rebind_configs if it doesn't exist yet.
	var colCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('rebind_configs') WHERE name='switch_at_time'`).Scan(&colCount)
	if colCount == 0 {
		if _, err = db.Exec(`ALTER TABLE rebind_configs ADD COLUMN switch_at_time DATETIME`); err != nil {
			return err
		}
	}
	return nil
}

// InsertInteraction persists an interaction and returns its new ID.
func (d *DB) InsertInteraction(i *Interaction) (int64, error) {
	res, err := d.Exec(`
		INSERT INTO interactions
			(uuid, type, timestamp, source_ip, query_name, query_type,
			 method, path, headers, body, user_agent, raw_data, decoded_data)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		i.UUID, i.Type, i.Timestamp, i.SourceIP, i.QueryName, i.QueryType,
		i.Method, i.Path, i.Headers, i.Body, i.UserAgent, i.RawData, i.DecodedData,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListInteractions returns interactions filtered by UUID and/or type with pagination.
// Pass empty strings to skip filters. limit=0 defaults to 200.
func (d *DB) ListInteractions(uuid, itype string, limit, offset int) ([]Interaction, error) {
	if limit <= 0 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT id,uuid,type,timestamp,source_ip,
		COALESCE(query_name,''), COALESCE(query_type,''),
		COALESCE(method,''), COALESCE(path,''),
		COALESCE(headers,''), COALESCE(body,''), COALESCE(user_agent,''),
		COALESCE(raw_data,''), COALESCE(decoded_data,'')
		FROM interactions WHERE 1=1`
	args := []any{}
	if uuid != "" {
		query += " AND uuid = ?"
		args = append(args, uuid)
	}
	if itype != "" {
		query += " AND type = ?"
		args = append(args, itype)
	}
	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Interaction
	for rows.Next() {
		var i Interaction
		if err := rows.Scan(&i.ID, &i.UUID, &i.Type, &i.Timestamp, &i.SourceIP,
			&i.QueryName, &i.QueryType, &i.Method, &i.Path,
			&i.Headers, &i.Body, &i.UserAgent, &i.RawData, &i.DecodedData,
		); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// GetStats returns interaction counts aggregated by type via SQL GROUP BY.
func (d *DB) GetStats() (*Stats, error) {
	stats := &Stats{ByType: make(map[string]int)}

	rows, err := d.Query("SELECT type, COUNT(*) FROM interactions GROUP BY type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var c int
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		stats.ByType[t] = c
		stats.Total += c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	_ = d.QueryRow(`SELECT COUNT(DISTINCT NULLIF(uuid,'')) FROM interactions`).Scan(&stats.UniqueUUIDs)
	return stats, nil
}

// DeleteInteractionsByUUID removes all interactions matching a UUID.
func (d *DB) DeleteInteractionsByUUID(uuid string) (int64, error) {
	res, err := d.Exec("DELETE FROM interactions WHERE uuid = ?", uuid)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UpsertRebindConfig creates or replaces a rebind configuration.
func (d *DB) UpsertRebindConfig(cfg *RebindConfig) error {
	_, err := d.Exec(`
		INSERT INTO rebind_configs (uuid, public_ip, private_ip, request_count, switch_after, switch_at_time)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(uuid) DO UPDATE SET
			public_ip=excluded.public_ip,
			private_ip=excluded.private_ip,
			request_count=0,
			switch_after=excluded.switch_after,
			switch_at_time=excluded.switch_at_time
	`, cfg.UUID, cfg.PublicIP, cfg.PrivateIP, 0, cfg.SwitchAfter, cfg.SwitchAtTime)
	return err
}

// GetRebindConfig returns a rebind config by UUID.
func (d *DB) GetRebindConfig(uuid string) (*RebindConfig, error) {
	var c RebindConfig
	var sat sql.NullTime
	err := d.QueryRow(`
		SELECT uuid, public_ip, private_ip, request_count, switch_after, switch_at_time
		FROM rebind_configs WHERE uuid = ?`, uuid,
	).Scan(&c.UUID, &c.PublicIP, &c.PrivateIP, &c.RequestCount, &c.SwitchAfter, &sat)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if sat.Valid {
		c.SwitchAtTime = &sat.Time
	}
	return &c, nil
}

// UpdateRebindCount increments the request counter for a rebind config.
func (d *DB) UpdateRebindCount(uuid string, count int) error {
	_, err := d.Exec("UPDATE rebind_configs SET request_count=? WHERE uuid=?", count, uuid)
	return err
}

// ValidateAPIKey returns true if the given key is active in the database.
func (d *DB) ValidateAPIKey(key string) bool {
	var n int
	_ = d.QueryRow("SELECT COUNT(*) FROM api_keys WHERE key_value=? AND active=1", key).Scan(&n)
	return n > 0
}
