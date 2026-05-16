package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
	Tags        []string  `json:"tags"`
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

// PayloadHistoryEntry records every payload generation for audit trail.
type PayloadHistoryEntry struct {
	ID        int64     `json:"id"`
	UUID      string    `json:"uuid"`
	Type      string    `json:"type"`
	Domain    string    `json:"domain"`
	Program   string    `json:"program"`
	Parameter string    `json:"parameter"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// UUIDSession stores the Bug Bounty context for a generated UUID.
type UUIDSession struct {
	ID        int64     `json:"id"`
	UUID      string    `json:"uuid"`
	Program   string    `json:"program"`
	Parameter string    `json:"parameter"`
	Endpoint  string    `json:"endpoint"`
	Notes     string    `json:"notes"`
	Status    string    `json:"status"` // "confirmed", "false_positive", "investigate", or ""
	CreatedAt time.Time `json:"created_at"`
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

		CREATE TABLE IF NOT EXISTS uuid_sessions (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid        TEXT    UNIQUE NOT NULL,
			program     TEXT    NOT NULL DEFAULT '',
			parameter   TEXT    NOT NULL DEFAULT '',
			endpoint    TEXT    NOT NULL DEFAULT '',
			notes       TEXT    NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_us_uuid    ON uuid_sessions(uuid);
		CREATE INDEX IF NOT EXISTS idx_us_program ON uuid_sessions(program);

		CREATE TABLE IF NOT EXISTS payload_history (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid       TEXT    NOT NULL,
			type       TEXT    NOT NULL,
			domain     TEXT    NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_ph_uuid    ON payload_history(uuid);
		CREATE INDEX IF NOT EXISTS idx_ph_created ON payload_history(created_at DESC);
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

	// Idempotent: add status column to uuid_sessions if it doesn't exist yet.
	var statusCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('uuid_sessions') WHERE name='status'`).Scan(&statusCount)
	if statusCount == 0 {
		if _, err = db.Exec(`ALTER TABLE uuid_sessions ADD COLUMN status TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}

	// Idempotent: add tags column to interactions if it doesn't exist yet.
	var tagsCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('interactions') WHERE name='tags'`).Scan(&tagsCount)
	if tagsCount == 0 {
		if _, err = db.Exec(`ALTER TABLE interactions ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'`); err != nil {
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

// ListInteractions returns interactions filtered by UUID, type, and/or tag with pagination.
// Pass empty strings to skip filters. limit=0 defaults to 200.
func (d *DB) ListInteractions(uuid, itype, tag string, limit, offset int) ([]Interaction, error) {
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
		COALESCE(raw_data,''), COALESCE(decoded_data,''), COALESCE(tags,'[]')
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
	if tag != "" {
		// JSON array stored as text; search for the exact quoted tag string.
		query += ` AND instr(tags, ?) > 0`
		args = append(args, `"`+tag+`"`)
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
		var tagsJSON string
		if err := rows.Scan(&i.ID, &i.UUID, &i.Type, &i.Timestamp, &i.SourceIP,
			&i.QueryName, &i.QueryType, &i.Method, &i.Path,
			&i.Headers, &i.Body, &i.UserAgent, &i.RawData, &i.DecodedData, &tagsJSON,
		); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(tagsJSON), &i.Tags)
		if i.Tags == nil {
			i.Tags = []string{}
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

// InsertPayloadHistory records a payload generation event.
func (d *DB) InsertPayloadHistory(uuid, ptype, domain string) error {
	_, err := d.Exec(`INSERT INTO payload_history (uuid, type, domain) VALUES (?,?,?)`, uuid, ptype, domain)
	return err
}

// ListPayloadHistory returns recent payload history joined with session context.
func (d *DB) ListPayloadHistory(limit int) ([]PayloadHistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Query(`
		SELECT ph.id, ph.uuid, ph.type, ph.domain, ph.created_at,
		       COALESCE(us.program,''), COALESCE(us.parameter,''), COALESCE(us.status,'')
		FROM payload_history ph
		LEFT JOIN uuid_sessions us ON ph.uuid = us.uuid
		ORDER BY ph.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PayloadHistoryEntry{}
	for rows.Next() {
		var e PayloadHistoryEntry
		if err := rows.Scan(&e.ID, &e.UUID, &e.Type, &e.Domain, &e.CreatedAt, &e.Program, &e.Parameter, &e.Status); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeletePayloadHistoryEntry removes a single history entry by ID.
func (d *DB) DeletePayloadHistoryEntry(id int64) error {
	_, err := d.Exec(`DELETE FROM payload_history WHERE id = ?`, id)
	return err
}

// UpsertSession creates or updates a UUID session (Bug Bounty context).
func (d *DB) UpsertSession(s *UUIDSession) error {
	_, err := d.Exec(`
		INSERT INTO uuid_sessions (uuid, program, parameter, endpoint, notes)
		VALUES (?,?,?,?,?)
		ON CONFLICT(uuid) DO UPDATE SET
			program=excluded.program,
			parameter=excluded.parameter,
			endpoint=excluded.endpoint,
			notes=excluded.notes`,
		s.UUID, s.Program, s.Parameter, s.Endpoint, s.Notes)
	return err
}

// GetSession returns the session for a UUID, or nil if not found.
func (d *DB) GetSession(uuid string) (*UUIDSession, error) {
	var s UUIDSession
	err := d.QueryRow(`
		SELECT id, uuid, program, parameter, endpoint, notes, COALESCE(status,''), created_at
		FROM uuid_sessions WHERE uuid = ?`, uuid,
	).Scan(&s.ID, &s.UUID, &s.Program, &s.Parameter, &s.Endpoint, &s.Notes, &s.Status, &s.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ListSessions returns all sessions, optionally filtered by program substring.
func (d *DB) ListSessions(program string) ([]UUIDSession, error) {
	query := `SELECT id, uuid, program, parameter, endpoint, notes, COALESCE(status,''), created_at FROM uuid_sessions WHERE 1=1`
	args := []any{}
	if program != "" {
		query += " AND program LIKE ?"
		args = append(args, "%"+program+"%")
	}
	query += " ORDER BY created_at DESC"

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []UUIDSession{}
	for rows.Next() {
		var s UUIDSession
		if err := rows.Scan(&s.ID, &s.UUID, &s.Program, &s.Parameter, &s.Endpoint, &s.Notes, &s.Status, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateSessionStatus sets the investigation status for a UUID.
// Upserts a minimal session record if none exists, so status can be set on ad-hoc UUIDs.
func (d *DB) UpdateSessionStatus(uuid, status string) error {
	_, err := d.Exec(`
		INSERT INTO uuid_sessions (uuid, status)
		VALUES (?, ?)
		ON CONFLICT(uuid) DO UPDATE SET status=excluded.status`,
		uuid, status)
	return err
}

// DeleteSession removes a session by UUID.
func (d *DB) DeleteSession(uuid string) error {
	_, err := d.Exec("DELETE FROM uuid_sessions WHERE uuid = ?", uuid)
	return err
}

// DeleteInteractionByID removes a single interaction by its primary key.
func (d *DB) DeleteInteractionByID(id int64) error {
	_, err := d.Exec("DELETE FROM interactions WHERE id = ?", id)
	return err
}

// CountInteractionsByUUID returns the number of interactions recorded for a UUID.
func (d *DB) CountInteractionsByUUID(uuid string) (int, error) {
	var n int
	err := d.QueryRow("SELECT COUNT(*) FROM interactions WHERE uuid = ?", uuid).Scan(&n)
	return n, err
}

// SearchInteractions performs a full-text LIKE search across all text fields.
func (d *DB) SearchInteractions(query string, limit, offset int) ([]Interaction, error) {
	if limit <= 0 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	term := "%" + query + "%"
	rows, err := d.Query(`
		SELECT id, uuid, type, timestamp, source_ip,
			COALESCE(query_name,''), COALESCE(query_type,''),
			COALESCE(method,''), COALESCE(path,''),
			COALESCE(headers,''), COALESCE(body,''), COALESCE(user_agent,''),
			COALESCE(raw_data,''), COALESCE(decoded_data,''), COALESCE(tags,'[]')
		FROM interactions
		WHERE uuid LIKE ? OR source_ip LIKE ? OR path LIKE ? OR query_name LIKE ?
		   OR user_agent LIKE ? OR headers LIKE ? OR body LIKE ?
		   OR raw_data LIKE ? OR decoded_data LIKE ?
		ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		term, term, term, term, term, term, term, term, term, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Interaction{}
	for rows.Next() {
		var i Interaction
		var tagsJSON string
		if err := rows.Scan(&i.ID, &i.UUID, &i.Type, &i.Timestamp, &i.SourceIP,
			&i.QueryName, &i.QueryType, &i.Method, &i.Path,
			&i.Headers, &i.Body, &i.UserAgent, &i.RawData, &i.DecodedData, &tagsJSON,
		); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(tagsJSON), &i.Tags)
		if i.Tags == nil {
			i.Tags = []string{}
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// GetInteractionByID returns a single interaction by its primary key.
func (d *DB) GetInteractionByID(id int64) (*Interaction, error) {
	var i Interaction
	var tagsJSON string
	err := d.QueryRow(`
		SELECT id,uuid,type,timestamp,source_ip,
			COALESCE(query_name,''), COALESCE(query_type,''),
			COALESCE(method,''), COALESCE(path,''),
			COALESCE(headers,''), COALESCE(body,''), COALESCE(user_agent,''),
			COALESCE(raw_data,''), COALESCE(decoded_data,''), COALESCE(tags,'[]')
		FROM interactions WHERE id=?`, id,
	).Scan(&i.ID, &i.UUID, &i.Type, &i.Timestamp, &i.SourceIP,
		&i.QueryName, &i.QueryType, &i.Method, &i.Path,
		&i.Headers, &i.Body, &i.UserAgent, &i.RawData, &i.DecodedData, &tagsJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(tagsJSON), &i.Tags)
	if i.Tags == nil {
		i.Tags = []string{}
	}
	return &i, nil
}

// AddInteractionTag appends a tag to an interaction (no-op if already present).
// Returns the updated tag list.
func (d *DB) AddInteractionTag(id int64, tag string) ([]string, error) {
	var raw string
	if err := d.QueryRow("SELECT COALESCE(tags,'[]') FROM interactions WHERE id=?", id).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("interaction %d not found", id)
		}
		return nil, err
	}
	var tags []string
	json.Unmarshal([]byte(raw), &tags)
	for _, t := range tags {
		if t == tag {
			return tags, nil
		}
	}
	tags = append(tags, tag)
	data, _ := json.Marshal(tags)
	_, err := d.Exec("UPDATE interactions SET tags=? WHERE id=?", string(data), id)
	return tags, err
}

// RemoveInteractionTag removes a tag from an interaction. Returns the updated list.
func (d *DB) RemoveInteractionTag(id int64, tag string) ([]string, error) {
	var raw string
	if err := d.QueryRow("SELECT COALESCE(tags,'[]') FROM interactions WHERE id=?", id).Scan(&raw); err != nil {
		return nil, err
	}
	var tags []string
	json.Unmarshal([]byte(raw), &tags)
	filtered := make([]string, 0, len(tags))
	for _, t := range tags {
		if t != tag {
			filtered = append(filtered, t)
		}
	}
	data, _ := json.Marshal(filtered)
	_, err := d.Exec("UPDATE interactions SET tags=? WHERE id=?", string(data), id)
	return filtered, err
}
