module firebird

// import time

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

fn test_open_no_db() {
	mut conn := new_connection('${protocol}${user}@${host}') or {
		assert true // protocol error: no database is provided
		return
	}
	conn.close() or { panic(err) }
}

fn test_open_() {
	mut conn := new_connection(url) or { panic(err) }
	conn.close() or { panic(err) }
}

fn test_new_statement() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	stmt.close()!

	tx.rollback()!
	conn.close()!
}

fn test_execute_statement_ddl_no_args() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	stmt.execute(no_args)!
	stmt.execute(no_args) or {
		// [firebird] unsuccessful metadata update
		// CREATE TABLE FOO failed
		// Table FOO already exists
		assert err.msg().contains('Table FOO already exists')
	}
	stmt.close()!

	stmt = tx.prepare_statement('DROP TABLE foo')!
	stmt.execute(no_args)!
	stmt.execute(no_args) or {
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

	mut result := tx.query('SELECT current_timestamp FROM RDB\$DATABASE', no_args)!
	mut columns := result.columns()
	assert columns.len == 1

	mut column := columns[0]
	assert column.field_name() == 'CURRENT_TIMESTAMP'
	assert column.sql_type() == 'TIMESTAMP WITH TIMEZONE'
	assert column.null_indicator == false

	mut rows := result.rows()
	assert rows.len == 1

	mut row := rows[0].values()
	assert row.len == 1

	mut t := row[0]
	assert t is Time && t.named_zone() == 'Etc/UTC'

	result = tx.query("
	SELECT current_timestamp AT TIME ZONE 'America/Sao_Paulo'
	FROM RDB\$DATABASE
	",
		no_args)!
	rows = result.rows()
	assert rows.len == 1

	row = rows[0].values()
	assert row.len == 1

	t = row[0]
	assert t is Time && t.named_zone() == 'America/Sao_Paulo'

	result = tx.query("SELECT TIME '12:00 GMT' AT TIME ZONE '-05:00' FROM RDB\$DATABASE",
		no_args)!
	rows = result.rows()
	assert rows.len == 1

	row = rows[0].values()
	assert row.len == 1

	t = row[0]
	assert t is Time && t.offset() == -300

	tx.rollback()!
	conn.close()!
}

fn test_time_zone() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.query('
		CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		time_with_timezone_col TIME WITH TIME ZONE,
		timestamp_with_timezone_col TIMESTAMP WITH TIME ZONE
		)',
		no_args)!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.query("
		INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (1, '16:03:00 +02:00', '2025-04-15 16:03:00 +14:00')
		",
		no_args)!

	tx.query("
		INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (2, '00:00:00 -05:30', '2000-01-01 00:00:00 -10:30')
		",
		no_args)!

	tx.query("
		INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (3, '23:59:59 Europe/Brussels', '1999-12-31 23:59:59 Europe/Brussels')
		",
		no_args)!

	result := tx.query('
		SELECT id, time_with_timezone_col, timestamp_with_timezone_col FROM foo',
		no_args)!

	columns := result.columns()
	assert columns.len == 3

	id_col := columns[0]
	t_tz_col := columns[1]
	ts_tz_col := columns[2]

	assert id_col.field_name() == 'ID'
	assert id_col.sql_type() == 'LONG'
	assert id_col.null_indicator() == false

	assert t_tz_col.field_name() == 'TIME_WITH_TIMEZONE_COL'
	assert t_tz_col.sql_type() == 'TIME WITH TIMEZONE'
	assert t_tz_col.null_indicator() == true

	assert ts_tz_col.field_name() == 'TIMESTAMP_WITH_TIMEZONE_COL'
	assert ts_tz_col.sql_type() == 'TIMESTAMP WITH TIMEZONE'
	assert ts_tz_col.null_indicator() == true

	rows := result.rows()
	assert rows.len == 3

	mut row := rows[0].values()
	assert row.len == 3

	mut id := row[0]
	mut t_tz := row[1]
	mut ts_tz := row[2]

	assert id is i32 && id == 1
	assert t_tz is Time && t_tz.offset() == 120
	assert ts_tz is Time && ts_tz.offset() == 840

	row = rows[1].values()
	assert row.len == 3

	id = row[0]
	t_tz = row[1]
	ts_tz = row[2]

	assert id is i32 && id == 2
	assert t_tz is Time && t_tz.offset() == -330
	assert ts_tz is Time && ts_tz.offset() == -630

	row = rows[2].values()
	assert row.len == 3

	id = row[0]
	t_tz = row[1]
	ts_tz = row[2]

	assert id is i32 && id == 3
	assert t_tz is Time && t_tz.named_zone() == 'Europe/Brussels'
	assert ts_tz is Time && ts_tz.named_zone() == 'Europe/Brussels'

	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.query('DROP TABLE foo', no_args)!
	tx.commit()!
	conn.close()!
}

// fn test_timestamp_tz_ex() {
// }

fn test_execute_dml_no_args() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement("
		CREATE TABLE foo (
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
	stmt.execute(no_args)!
	stmt.close()!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	stmt = tx.prepare_statement("
		INSERT INTO foo (a, b, c, h)
			VALUES (1, 'a', 'b', 'This is a test')")!
	stmt.execute(no_args)!
	stmt.execute(no_args) or {
		// [firebird] violation of PRIMARY or UNIQUE KEY constraint "INTEG_83" on table "FOO"
		// Problematic key value is ("B" = 'a')
		assert err.msg().contains('violation of PRIMARY or UNIQUE KEY constraint')
	}
	stmt.close()!

	result := tx.query('SELECT a, b, c, h FROM foo', no_args)!

	rows := result.rows()
	assert rows.len == 1

	row := rows[0].values()
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
	tx.query('DROP TABLE foo', no_args)!
	tx.commit()!
	conn.close()!
}

fn test_null() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement('
		CREATE TABLE foo (
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
	stmt.execute(no_args)!
	stmt.close()!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	stmt = tx.prepare_statement('INSERT INTO foo (id) VALUES (1)')!
	stmt.execute(no_args)!
	stmt.close()!

	stmt = tx.prepare_statement('SELECT a, b, c, d, e, f, g, h FROM foo')!
	result := stmt.execute(no_args)!

	rows := result.rows()
	assert rows.len == 1

	row := rows[0].values()
	assert row.len == 8

	for i := 0; i < row.len; i++ {
		assert row[i] is Null
	}

	stmt.close()!
	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.query('DROP TABLE foo', no_args)!
	tx.commit()!
	conn.close()!
}

fn test_statement_params() {
	mut conn := new_connection(url)!

	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement('
		CREATE TABLE foo (
			id INTEGER PRIMARY KEY,
			a INTEGER,
			b VARCHAR(1024),
			c DECIMAL(16,3),
			d BLOB SUB_TYPE TEXT,
			e DOUBLE PRECISION,
			f REAL
			)')!
	stmt.execute(no_args)!
	stmt.close()!
	tx.commit()!

	tx = conn.start_transaction(isolation_level_read_commited)!

	stmt = tx.prepare_statement('INSERT INTO foo (id) VALUES (?)')!
	mut args := [Value(i32(1))]
	stmt.execute(args)!
	stmt.close()!

	stmt = tx.prepare_statement('INSERT INTO foo (id, a) VALUES (?, ?)')!
	args = [Value(i32(2)), i32(10)]
	stmt.execute(args)!

	args = [Value(i32(3)), i32(20)]
	stmt.execute(args)!
	stmt.close()!

	stmt = tx.prepare_statement('INSERT INTO foo (id, a, b, d) VALUES (?, ?, ?, ?)')!
	args = [Value(i32(4)), i32(100), 'this is a varchar field', 'this is a blob field']
	stmt.execute(args)!
	stmt.close()!

	stmt = tx.prepare_statement('INSERT INTO foo (id, a, e, f) VALUES (?, ?, ?, ?)')!
	args = [Value(i32(5)), i32(1000), f64(6.02214), f32(3.14)]
	stmt.execute(args)!
	stmt.close()!

	// stmt = tx.prepare_statement('INSERT INTO foo (id, a, b, d,f) VALUES (?, ?, ?, ?, ?)')!
	// args = [
	// 	Value(i32(6)),
	// 	i32(1000),
	// 	'this is a varchar field',
	// 	'this is a blob field',
	// 	f64(3.14),
	// ]
	// stmt.execute(args)! // invalid copy of buffer, happens at BufferedReader.read in WireProtocol.generic_response
	// // What causes it?

	stmt = tx.prepare_statement('SELECT * FROM foo')!
	result := stmt.execute(no_args)!

	columns := result.columns()
	rows := result.rows()
	assert rows.len == 5

	mut row := rows[0].values()
	for i := 0; i < row.len; i++ {
		c := columns[i]
		v := row[i]
		if c.field_name() == 'ID' {
			assert v is i32 && v == 1
		} else {
			assert v is Null
		}
	}

	row = rows[1].values()
	for i := 0; i < row.len; i++ {
		c := columns[i]
		v := row[i]
		if c.field_name() == 'ID' {
			assert v is i32 && v == 2
		} else if c.field_name() == 'A' {
			assert v is i32 && v == 10
		} else {
			assert v is Null
		}
	}

	row = rows[2].values()
	for i := 0; i < row.len; i++ {
		c := columns[i]
		v := row[i]
		if c.field_name() == 'ID' {
			assert v is i32 && v == 3
		} else if c.field_name() == 'A' {
			assert v is i32 && v == 20
		} else {
			assert v is Null
		}
	}

	row = rows[3].values()
	for i := 0; i < row.len; i++ {
		c := columns[i]
		v := row[i]
		if c.field_name() == 'ID' {
			assert v is i32 && v == 4
		} else if c.field_name() == 'A' {
			assert v is i32 && v == 100
		} else if c.field_name() == 'B' {
			assert v is string && v == 'this is a varchar field'
		} else if c.field_name() == 'D' {
			assert v is string && v == 'this is a blob field'
		} else {
			assert v is Null
		}
	}

	row = rows[4].values()
	for i := 0; i < row.len; i++ {
		c := columns[i]
		v := row[i]
		if c.field_name() == 'ID' {
			assert v is i32 && v == 5
		} else if c.field_name() == 'A' {
			assert v is i32 && v == 1000
		} else if c.field_name() == 'E' {
			assert v is f64 && v == f64(6.02214)
		} else if c.field_name() == 'F' {
			assert v is f32 && v == f32(3.14)
		} else {
			assert v is Null
		}
	}

	stmt.close()!

	// stmt = tx.prepare_statement('INSERT INTO foo (id, a, b, c, f, g, h)
	// 	VALUES (? ,? ,? ,? ,? ,? ,?)')!

	// args = [
	// 	Value(i32(12)), // INTEGER
	// 	i32(69), // INTEGER
	// 	'this is a test', // VARCHAR
	// 	f64(4.20), // DECIMAL
	// 	'this is supposed to be a blob', // BLOB SUB_TYPE TEXT
	// 	f64(3.14), // DOUBLE PRECISION
	// 	f64(6.02214076), // REAL
	// ]
	// stmt.execute(args)!
	// stmt.close()!

	tx.rollback()!

	tx = conn.start_transaction(isolation_level_read_commited)!
	tx.query('DROP TABLE foo', no_args)!
	tx.commit()!
	conn.close()!
}

// fn test_statement_time_params() {
// 	mut conn := new_connection(url)!

// 	mut tx := conn.start_transaction(isolation_level_read_commited)!
// 	mut stmt := tx.prepare_statement('
// 		CREATE TABLE foo (
// 			id INTEGER PRIMARY KEY,
// 			a DATE,
// 			b TIME,
// 			c TIME WITH TIME ZONE,
// 			d TIMESTAMP,
// 			e TIMESTAMP WITH TIME ZONE
// 			)')!
// 	stmt.execute(no_args)!
// 	stmt.close()!
// 	tx.commit()!

// 	tx = conn.start_transaction(isolation_level_read_commited)!
// 	stmt = tx.prepare_statement('INSERT INTO foo (id, a, d) VALUES (?, ?, ?)')!

// 	mut date := Time{
// 		sql_type:  sql_type_date
// 		timestamp: time.parse_iso8601('2025-02-12')!
// 	}

// 	mut timestamp := Time{
// 		sql_type:  sql_type_timestamp
// 		timestamp: time.now()
// 	}

// 	mut args := [Value(i32(1)), date, timestamp]
// 	stmt.execute(args)!
// 	stmt.close()!

// 	stmt = tx.prepare_statement('SELECT * FROM foo')!
// 	result := stmt.execute(no_args)!

// 	columns := result.columns()
// 	rows := result.rows()
// 	assert rows.len == 1

// 	mut row := rows[0].values()
// 	println(row)

// tx = conn.start_transaction(isolation_level_read_commited)!
// tx.query('DROP TABLE foo', no_args)!
// tx.commit()!
// conn.close()!
// }
