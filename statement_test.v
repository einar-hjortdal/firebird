module firebird

import time
import einar_hjortdal.luuid

// To manually fix issues:
// sudo docker run \
//   --rm \
//   -it \
//   --name=firebird-client \
//   --network=host \
//   firebirdsql/firebird \
//   isql -u fbusr -p fbpwd localhost:/var/lib/firebird/data/firebird.fdb

const protocol = 'firebird://'
const user = 'fbusr'
const password = 'fbpwd'
const host = '127.0.0.1:3050'
const database = '/var/lib/firebird/data/firebird.fdb'
const url = '${protocol}${user}:${password}@${host}${database}'

// TODO cleanup functions: ensure manual intervention is never needed.
// TODO use get_type utility functions to simplify assertions
// TODO split DateTime params tests from date string params

fn test_open_no_db() {
	mut conn := new_connection('${protocol}${user}@${host}') or {
		assert true // protocol error: no database is provided
		return
	}
	conn.close()!
}

fn test_open() {
	mut conn := new_connection(url)!
	conn.close()!
}

fn test_new_statement() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut stmt := tx.prepare('CREATE TABLE foo (a INTEGER)')!
	stmt.close()!

	tx.rollback()!
	conn.close()!
}

fn test_execute_statement_ddl() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut stmt := tx.prepare('CREATE TABLE foo (a INTEGER)')!
	stmt.execute()!
	stmt.execute() or {
		// [firebird] unsuccessful metadata update
		// CREATE TABLE FOO failed
		// Table FOO already exists
		assert err.msg().contains('Table FOO already exists')
	}
	stmt.close()!

	stmt = tx.prepare('DROP TABLE foo')!
	stmt.execute()!
	stmt.execute() or {
		// [firebird] unsuccessful metadata update
		// DROP TABLE FOO failed
		// SQL error code = -607
		// Invalid command
		// Table FOO does not exist
		assert err.msg().contains('Table FOO does not exist')
	}
	stmt.close()!

	tx.rollback()!
	conn.close()!
}

fn test_at_time_zone() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut result := tx.execute('SELECT current_timestamp FROM RDB\$DATABASE')!
	assert result.columns.len == 1

	mut column := result.columns[0]
	assert column.field_name == 'CURRENT_TIMESTAMP'
	assert column.sql_type == 'TIMESTAMP WITH TIMEZONE'
	assert column.null_indicator == false

	assert result.rows.len == 1

	assert result.rows[0].values.len == 1

	mut t := result.rows[0].values[0]
	assert t is DateTime && t.named_zone == 'Etc/UTC'

	result = tx.execute("SELECT current_timestamp AT TIME ZONE 'America/Sao_Paulo'
		FROM RDB\$DATABASE")!
	assert result.rows.len == 1

	assert result.rows[0].values.len == 1

	t = result.rows[0].values[0]
	assert t is DateTime && t.named_zone == 'America/Sao_Paulo'

	result = tx.execute("SELECT TIME '12:00 GMT' AT TIME ZONE '-05:00' FROM RDB\$DATABASE")!
	assert result.rows.len == 1

	assert result.rows[0].values.len == 1

	t = result.rows[0].values[0]
	assert t is DateTime && t.offset == -300

	tx.rollback()!
	conn.close()!
}

fn test_time_zone() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.execute('CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		time_with_timezone_col TIME WITH TIME ZONE,
		timestamp_with_timezone_col TIMESTAMP WITH TIME ZONE)')!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute("INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (1, '16:03:00 +02:00', '2025-04-15 16:03:00 +14:00')")!

	tx.execute("INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (2, '00:00:00 -05:30', '2000-01-01 00:00:00 -10:30')")!

	tx.execute("INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (3, '23:59:59 Europe/Brussels', '1999-12-31 23:59:59 Europe/Brussels')")!

	result := tx.execute('
		SELECT id, time_with_timezone_col, timestamp_with_timezone_col FROM foo')!

	columns := result.columns
	assert columns.len == 3

	id_col := columns[0]
	t_tz_col := columns[1]
	ts_tz_col := columns[2]

	assert id_col.field_name == 'ID'
	assert id_col.sql_type == 'LONG'
	assert id_col.null_indicator == false

	assert t_tz_col.field_name == 'TIME_WITH_TIMEZONE_COL'
	assert t_tz_col.sql_type == 'TIME WITH TIMEZONE'
	assert t_tz_col.null_indicator == true

	assert ts_tz_col.field_name == 'TIMESTAMP_WITH_TIMEZONE_COL'
	assert ts_tz_col.sql_type == 'TIMESTAMP WITH TIMEZONE'
	assert ts_tz_col.null_indicator == true

	assert result.rows.len == 3

	assert result.rows[0].values.len == 3

	mut id := result.rows[0].values[0]
	mut t_tz := result.rows[0].values[1]
	mut ts_tz := result.rows[0].values[2]

	assert id is i32 && id == 1
	assert t_tz is DateTime && t_tz.offset == 120
	assert ts_tz is DateTime && ts_tz.offset == 840

	assert result.rows[1].values.len == 3

	id = result.rows[1].values[0]
	t_tz = result.rows[1].values[1]
	ts_tz = result.rows[1].values[2]

	assert id is i32 && id == 2
	assert t_tz is DateTime && t_tz.offset == -330
	assert ts_tz is DateTime && ts_tz.offset == -630

	assert result.rows[2].values.len == 3

	id = result.rows[2].values[0]
	t_tz = result.rows[2].values[1]
	ts_tz = result.rows[2].values[2]

	assert id is i32 && id == 3
	assert t_tz is DateTime && t_tz.named_zone == 'Europe/Brussels'
	assert ts_tz is DateTime && ts_tz.named_zone == 'Europe/Brussels'

	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

// fn test_timestamp_tz_ex() {
// }

fn test_execute_dml() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare("CREATE TABLE foo (
		a INTEGER NOT NULL,
		b VARCHAR(30) NOT NULL UNIQUE,
		c VARCHAR(1024),
		d DECIMAL(16,3) DEFAULT -0.123,
		e DATE DEFAULT '1967-08-11',
		f TIMESTAMP DEFAULT '1967-08-11 23:45:01',
		g TIME DEFAULT '23:45:01',
		h BLOB SUB_TYPE TEXT,
		i DOUBLE PRECISION DEFAULT 0.0,
		j FLOAT DEFAULT 0.0,
		PRIMARY KEY (a),
		CONSTRAINT CHECK_A CHECK (a <> 0)
		)")!
	stmt.execute()!
	stmt.close()!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	stmt = tx.prepare("INSERT INTO foo (a, b, c, h) VALUES (1, 'a', 'b', 'This is a test')")!
	stmt.execute()!
	stmt.execute() or {
		// [firebird] violation of PRIMARY or UNIQUE KEY constraint "INTEG_83" on table "FOO"
		// Problematic key value is ("B" = 'a')
		assert err.msg().contains('violation of PRIMARY or UNIQUE KEY constraint')
	}
	stmt.close()!

	result := tx.execute('SELECT a, b, c, h FROM foo')!

	rows := result.rows
	assert rows.len == 1

	row := rows[0].values
	assert row.len == 4

	a_value := row[0]
	assert a_value is i32 && a_value == 1

	b_value := row[1]
	assert b_value is string && b_value == 'a'

	c_value := row[2]
	assert c_value is string && c_value == 'b'

	h_value := row[3]
	assert h_value is string && h_value == 'This is a test'

	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_null() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare('CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		a INTEGER,
		b VARCHAR(1024),
		c DECIMAL(16,3),
		d DATE,
		e TIMESTAMP,
		f BLOB SUB_TYPE TEXT,
		g DOUBLE PRECISION,
		h REAL
		)')!
	stmt.execute()!
	stmt.close()!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	stmt = tx.prepare('INSERT INTO foo (id) VALUES (1)')!
	stmt.execute()!
	stmt.close()!

	stmt = tx.prepare('SELECT a, b, c, d, e, f, g, h FROM foo')!
	result := stmt.execute()!

	rows := result.rows
	assert rows.len == 1

	row := rows[0].values
	assert row.len == 8

	for i := 0; i < row.len; i++ {
		assert row[i] is Null
	}

	stmt.close()!
	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_statement_params() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.execute('CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		a INTEGER,
		b VARCHAR(1024),
		c DECIMAL(16,3),
		d BLOB SUB_TYPE TEXT,
		e DOUBLE PRECISION,
		f REAL
		)')!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!

	tx.execute('INSERT INTO foo (id) VALUES (?)', i32(1))!

	mut stmt := tx.prepare('INSERT INTO foo (id, a) VALUES (?, ?)')!
	stmt.execute(i32(2), i32(10))!
	stmt.execute(i32(3), i32(20))!
	stmt.close()!

	tx.execute('INSERT INTO foo (id, a, b, d) VALUES (?, ?, ?, ?)', i32(4), i32(100),
		'this is a varchar field', 'this is a blob field')!

	tx.execute('INSERT INTO foo (id, a, e, f) VALUES (?, ?, ?, ?)', i32(5), i32(1000),
		f64(6.02214), f32(3.14))!

	tx.execute('INSERT INTO foo (id, a, b, d, f) VALUES (?, ?, ?, ?, ?)', i32(6), i32(1000),
		'this is a varchar field', 'this is a blob field', f32(3.14))!

	// stmt = tx.prepare('INSERT INTO foo (id, a, b, c, f, g, h)
	// 	VALUES (? ,? ,? ,? ,? ,? ,?)')!

	// params = [
	// 	Value(i32(7)), // INTEGER
	// 	i32(69), // INTEGER
	// 	'this is a test', // VARCHAR
	// 	f64(4.20), // DECIMAL
	// 	'this is supposed to be a blob', // BLOB SUB_TYPE TEXT
	// 	f64(3.14), // DOUBLE PRECISION
	// 	f64(6.02214076), // REAL
	// ]
	// stmt.execute(...params)!
	// stmt.close()!

	result := tx.execute('SELECT * FROM foo')!

	assert result.rows.len == 6

	for i := 0; i < result.rows[0].values.len; i++ {
		c := result.columns[i]
		v := result.rows[0].values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 1
		} else {
			assert v is Null
		}
	}

	for i := 0; i < result.rows[1].values.len; i++ {
		c := result.columns[i]
		v := result.rows[1].values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 2
		} else if c.field_name == 'A' {
			assert v is i32 && v == 10
		} else {
			assert v is Null
		}
	}

	for i := 0; i < result.rows[2].values.len; i++ {
		c := result.columns[i]
		v := result.rows[2].values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 3
		} else if c.field_name == 'A' {
			assert v is i32 && v == 20
		} else {
			assert v is Null
		}
	}

	for i := 0; i < result.rows[3].values.len; i++ {
		c := result.columns[i]
		v := result.rows[3].values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 4
		} else if c.field_name == 'A' {
			assert v is i32 && v == 100
		} else if c.field_name == 'B' {
			assert v is string && v == 'this is a varchar field'
		} else if c.field_name == 'D' {
			assert v is string && v == 'this is a blob field'
		} else {
			assert v is Null
		}
	}

	for i := 0; i < result.rows[4].values.len; i++ {
		c := result.columns[i]
		v := result.rows[4].values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 5
		} else if c.field_name == 'A' {
			assert v is i32 && v == 1000
		} else if c.field_name == 'E' {
			assert v is f64 && v == f64(6.02214)
		} else if c.field_name == 'F' {
			assert v is f32 && v == f32(3.14)
		} else {
			assert v is Null
		}
	}

	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_statement_time_params() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.execute('CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		a DATE,
		b TIME,
		c TIME WITH TIME ZONE,
		d TIMESTAMP,
		e TIMESTAMP WITH TIME ZONE
		)')!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!

	// string params
	tx.execute('INSERT INTO foo (id, a) VALUES (?, ?)', i32(1), '2025-02-12')!
	tx.execute('INSERT INTO foo (id, b) VALUES (?, ?)', i32(2), '12:34:56')!
	tx.execute('INSERT INTO foo (id, c) VALUES (?, ?)', i32(3), '12:34:56 +02:00')!
	tx.execute('INSERT INTO foo (id, d) VALUES (?, ?)', i32(4), '2025-02-12 12:34:56')!
	tx.execute('INSERT INTO foo (id, e) VALUES (?, ?)', i32(5), '2025-02-12 12:34:56 Europe/Brussels')!

	// same data, but as DateTime objects
	d := new_date(time.parse_iso8601('2025-02-12')!)
	tx.execute('INSERT INTO foo (id, a) VALUES (?, ?)', i32(6), d)!

	t := new_time(time.parse_iso8601('2025-02-12T12:34:56')!)
	tx.execute('INSERT INTO foo (id, b) VALUES (?, ?)', i32(7), t)!

	t_tz := new_time_tz_offset(time.parse_iso8601('2025-02-12T12:34:56')!, 120)!
	tx.execute('INSERT INTO foo (id, c) VALUES (?, ?)', i32(8), t_tz)!

	ts := new_timestamp(time.parse_iso8601('2025-02-12T12:34:56Z')!)
	tx.execute('INSERT INTO foo (id, d) VALUES (?, ?)', i32(9), ts)!

	ts_tz := new_timestamp_tz_named_zone(time.parse_iso8601('2025-02-12T12:34:56Z')!,
		'Europe/Brussels')!
	tx.execute('INSERT INTO foo (id, e) VALUES (?, ?)', i32(10), ts_tz)!

	result := tx.execute('SELECT * FROM foo')!
	columns := result.columns
	rows := result.rows
	assert rows.len == 10

	mut id_string, _ := rows[0].values[0].get_i32()!
	mut id_date_time, _ := rows[5].values[0].get_i32()!
	mut v_string, _ := rows[0].values[1].get_date_time()!
	mut v_date_time, _ := rows[5].values[1].get_date_time()!

	assert id_string == 1
	assert id_date_time == 6
	assert v_string.Time.year == 2025
	assert v_date_time.Time.year == 2025
	assert v_string.Time.month == 2
	assert v_date_time.Time.month == 2
	assert v_string.Time.day == 12
	assert v_date_time.Time.day == 12

	id_string, _ = rows[1].values[0].get_i32()!
	id_date_time, _ = rows[6].values[0].get_i32()!
	v_string, _ = rows[1].values[2].get_date_time()!
	v_date_time, _ = rows[6].values[2].get_date_time()!

	assert id_string == 2
	assert id_date_time == 7
	assert v_string.Time.hour == 12
	assert v_date_time.Time.hour == 12
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56

	id_string, _ = rows[2].values[0].get_i32()!
	id_date_time, _ = rows[7].values[0].get_i32()!
	v_string, _ = rows[2].values[3].get_date_time()!
	v_date_time, _ = rows[7].values[3].get_date_time()!

	assert id_string == 3
	assert id_date_time == 8
	assert v_string.Time.hour == 10
	// When a timestamp is inserted in Firebird as DateTime, the offset is not added to Time.time
	assert v_date_time.Time.hour == 12
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56
	assert v_string.offset == 120
	assert v_date_time.offset == 120

	id_string, _ = rows[3].values[0].get_i32()!
	id_date_time, _ = rows[8].values[0].get_i32()!
	v_string, _ = rows[3].values[4].get_date_time()!
	v_date_time, _ = rows[8].values[4].get_date_time()!

	assert id_string == 4
	assert id_date_time == 9
	assert v_string.Time.year == 2025
	assert v_date_time.Time.year == 2025
	assert v_string.Time.month == 2
	assert v_date_time.Time.month == 2
	assert v_string.Time.day == 12
	assert v_date_time.Time.day == 12
	assert v_string.Time.hour == 12
	assert v_date_time.Time.hour == 12
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56

	id_string, _ = rows[4].values[0].get_i32()!
	id_date_time, _ = rows[9].values[0].get_i32()!
	v_string, _ = rows[4].values[5].get_date_time()!
	v_date_time, _ = rows[9].values[5].get_date_time()!

	assert id_string == 5
	assert id_date_time == 10
	assert v_string.Time.year == 2025
	assert v_date_time.Time.year == 2025
	assert v_string.Time.month == 2
	assert v_date_time.Time.month == 2
	assert v_string.Time.day == 12
	assert v_date_time.Time.day == 12
	// Hour is not checked because named_zone behavior may change?
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56
	assert v_string.named_zone == 'Europe/Brussels'
	assert v_date_time.named_zone == 'Europe/Brussels'

	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_luuid() {
	mut gen := luuid.new_generator()
	id := gen.v1()
	id_bin := luuid.to_bytes(id)!

	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.execute('CREATE TABLE foo (
		id BINARY(16) PRIMARY KEY NOT NULL,
		a BINARY(16)
		)')!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!

	// This query inserts id using CHAT_TO_UUID in the column id, and id as []u8 in the column a
	tx.execute('INSERT INTO foo (id, a) VALUES (CHAR_TO_UUID(?), ?)', id, id_bin)!

	// The following query will prove that firebirds stores id and a identically
	res := tx.execute('SELECT UUID_TO_CHAR(id), a FROM foo WHERE id = a')!
	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!

	conn.close()!

	// If the value in both columns is the same, we expect one row of results.
	assert res.rows.len == 1

	// Now the row values are converted and compared at the app level
	got_id, _ := res.rows[0].values[0].get_string()!
	a_bin, _ := res.rows[0].values[1].get_array_u8()!
	got_a := luuid.from_bytes(a_bin)!

	// got_id contains whitespaces that needs to be trimmed.
	// Don't know why this happens. got.id.len == 144, 4 times 36.
	// The firebird server sends this array as text with utf8 encoding
	// [48, 54, 56, 50, 52, 53, 53, 70, 45, 55, 50, 49, 52, 45, 49, 66, 52, 66, 45, 51, 67, 48, 48, 45, 55, 49, 68, 66, 69, 57, 69, 57, 65, 69, 48, 67, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32]
	// All those 32 after the id make no sense to me.
	//
	// got_a needs to be normalized to uppercase because firebird always normalizes to uppercase.
	assert got_id.trim_space() == got_a.to_upper()
}

fn test_char_boolean() {
	mut conn := new_connection('${protocol}${user}@${host}') or {
		assert true // protocol error: no database is provided
		return
	}
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.execute('CREATE TABLE foo (
		id CHAR(3) PRIMARY KEY NOT NULL,
		includes_tax BOOLEAN DEFAULT true
		)')!
	tx.commit()!

	id := 'EUR'

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('INSERT INTO foo (id) VALUES (?)', id)!
	mut r := tx.execute('SELECT id, includes_tax FROM foo WHERE id = ?', 1)!
	assert r.rows.len == 1
	mut v, mut v_is_null := r.rows[0].values[1].get_bool()!
	assert v == true

	r = tx.execute('UPDATE foo SET includes_tax = ? WHERE id = ?', false, id)!
	v, v_is_null = r.rows[0].values[1].get_bool()!
	assert v == false

	r = tx.execute('UPDATE foo SET a = ? WHERE id = ?', true, id)!
	v, v_is_null = r.rows[0].values[1].get_bool()!
	assert v == true

	r = tx.execute('UPDATE foo SET a = ? WHERE id = ?', Null{}, id)!
	v, v_is_null = r.rows[0].values[1].get_bool()!
	assert v == false
	assert v_is_null == true

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!

	conn.close()!
}
