module tests

import firebird

fn testsuite_begin() ! {
	container_firebird_start()!
	container_is_ready()
}

fn testsuite_end() ! {
	container_firebird_clean()
}

// TODO use get_type utility functions to simplify assertions
// TODO split DateTime params tests from date string params

fn test_open_no_db() {
	mut conn := firebird.new_connection('firebird://${firebird_user}:${firebird_password}@localhost') or {
		assert true // protocol error: no database is provided
		return
	}
	conn.close()!
}

fn test_open() {
	mut conn := firebird.new_connection(firebird_url)!
	conn.close()!
}

fn test_new_statement() {
	mut conn := firebird.new_connection(firebird_url)!
	mut tx := start_transaction(mut conn)!

	mut stmt := tx.prepare('CREATE TABLE foo (a INTEGER)')!
	stmt.close()!

	tx.rollback()!
	conn.close()!
}

fn test_execute_statement_ddl() {
	mut conn := firebird.new_connection(firebird_url)!
	mut tx := start_transaction(mut conn)!

	mut stmt := tx.prepare('CREATE TABLE foo (a INTEGER)')!
	mut result := stmt.execute()!
	assert result.affected_rows() == 0

	stmt.execute() or {
		// [firebird] unsuccessful metadata update
		// CREATE TABLE FOO failed
		// Table FOO already exists
		assert err.msg().contains('Table FOO already exists')
	}
	stmt.close()!

	stmt = tx.prepare('DROP TABLE foo')!
	result = stmt.execute()!
	assert result.affected_rows() == 0

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
	mut conn := firebird.new_connection(firebird_url)!
	mut tx := start_transaction(mut conn)!

	mut result := tx.execute('SELECT current_timestamp FROM RDB\$DATABASE')!
	mut columns := result.columns()
	assert columns.len == 1

	mut c := columns[0]
	assert c.field_name == 'CURRENT_TIMESTAMP'
	assert c.sql_type == 'TIMESTAMP WITH TIMEZONE'
	assert c.null_indicator == false

	mut rows := result.rows()
	assert rows.len == 1
	assert rows[0].values().len == 1

	mut t := rows[0].values()[0]
	assert t is firebird.DateTime && t.named_zone == 'Etc/UTC'

	result = tx.execute("SELECT current_timestamp AT TIME ZONE 'America/Sao_Paulo'
		FROM RDB\$DATABASE")!
	rows = result.rows()
	assert rows.len == 1
	assert rows[0].values().len == 1

	t = rows[0].values()[0]
	assert t is firebird.DateTime && t.named_zone == 'America/Sao_Paulo'

	result = tx.execute("SELECT TIME '12:00 GMT' AT TIME ZONE '-05:00' FROM RDB\$DATABASE")!
	rows = result.rows()
	assert rows.len == 1
	assert rows[0].values().len == 1

	t = rows[0].values()[0]
	assert t is firebird.DateTime && t.offset == -300

	tx.rollback()!
	conn.close()!
}

fn test_time_zone() {
	mut conn := firebird.new_connection(firebird_url)!
	mut tx := start_transaction(mut conn)!
	tx.execute('CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		time_with_timezone_col TIME WITH TIME ZONE,
		timestamp_with_timezone_col TIMESTAMP WITH TIME ZONE)')!
	tx.commit()!

	tx = start_transaction(mut conn)!
	mut result := tx.execute("INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (1, '16:03:00 +02:00', '2025-04-15 16:03:00 +14:00')")!
	assert result.affected_rows() == 1

	tx.execute("INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (2, '00:00:00 -05:30', '2000-01-01 00:00:00 -10:30')")!

	tx.execute("INSERT INTO foo (id, time_with_timezone_col, timestamp_with_timezone_col)
		VALUES (3, '23:59:59 Europe/Brussels', '1999-12-31 23:59:59 Europe/Brussels')")!

	result = tx.execute('
		SELECT id, time_with_timezone_col, timestamp_with_timezone_col FROM foo')!

	columns := result.columns()
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

	rows := result.rows()
	assert rows.len == 3

	mut values := rows[0].values()
	assert values.len == 3

	mut id := values[0]
	mut t_tz := values[1]
	mut ts_tz := values[2]

	assert id is i32 && id == 1
	assert t_tz is firebird.DateTime && t_tz.offset == 120
	assert ts_tz is firebird.DateTime && ts_tz.offset == 840

	values = rows[1].values()
	assert values.len == 3

	id = values[0]
	t_tz = values[1]
	ts_tz = values[2]

	assert id is i32 && id == 2
	assert t_tz is firebird.DateTime && t_tz.offset == -330
	assert ts_tz is firebird.DateTime && ts_tz.offset == -630

	values = rows[2].values()
	assert values.len == 3

	id = values[0]
	t_tz = values[1]
	ts_tz = values[2]

	assert id is i32 && id == 3
	assert t_tz is firebird.DateTime && t_tz.named_zone == 'Europe/Brussels'
	assert ts_tz is firebird.DateTime && ts_tz.named_zone == 'Europe/Brussels'

	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

// fn test_timestamp_tz_ex() {
// }

fn test_execute_dml() {
	mut conn := firebird.new_connection(firebird_url)!

	mut tx := start_transaction(mut conn)!
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

	tx = start_transaction(mut conn)!
	stmt = tx.prepare("INSERT INTO foo (a, b, c, h) VALUES (1, 'a', 'b', 'This is a test')")!
	stmt.execute()!
	stmt.execute() or {
		// [firebird] violation of PRIMARY or UNIQUE KEY constraint "INTEG_83" on table "FOO"
		// Problematic key value is ("B" = 'a')
		assert err.msg().contains('violation of PRIMARY or UNIQUE KEY constraint')
	}
	stmt.close()!

	result := tx.execute('SELECT a, b, c, h FROM foo')!

	rows := result.rows()
	assert rows.len == 1

	values := rows[0].values()
	assert values.len == 4

	a_value := values[0]
	assert a_value is i32 && a_value == 1

	b_value := values[1]
	assert b_value is string && b_value == 'a'

	c_value := values[2]
	assert c_value is string && c_value == 'b'

	h_value := values[3]
	assert h_value is string && h_value == 'This is a test'

	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_null() {
	mut conn := firebird.new_connection(firebird_url)!

	mut tx := start_transaction(mut conn)!
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

	tx = start_transaction(mut conn)!
	stmt = tx.prepare('INSERT INTO foo (id) VALUES (1)')!
	stmt.execute()!
	stmt.close()!

	stmt = tx.prepare('SELECT a, b, c, d, e, f, g, h FROM foo')!
	result := stmt.execute()!

	rows := result.rows()
	assert rows.len == 1

	values := rows[0].values()
	assert values.len == 8

	for i := 0; i < values.len; i++ {
		assert values[i] is firebird.Null
	}

	stmt.close()!
	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_statement_params() {
	mut conn := firebird.new_connection(firebird_url)!

	mut tx := start_transaction(mut conn)!
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

	tx = start_transaction(mut conn)!

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

	rows := result.rows()
	assert rows.len == 6

	mut values := rows[0].values()
	for i := 0; i < values.len; i++ {
		c := result.columns()[i]
		v := values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 1
		} else {
			assert v is firebird.Null
		}
	}

	values = rows[1].values()
	for i := 0; i < values.len; i++ {
		c := result.columns()[i]
		v := values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 2
		} else if c.field_name == 'A' {
			assert v is i32 && v == 10
		} else {
			assert v is firebird.Null
		}
	}

	values = rows[2].values()
	for i := 0; i < values.len; i++ {
		c := result.columns()[i]
		v := values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 3
		} else if c.field_name == 'A' {
			assert v is i32 && v == 20
		} else {
			assert v is firebird.Null
		}
	}

	values = rows[3].values()
	for i := 0; i < values.len; i++ {
		c := result.columns()[i]
		v := values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 4
		} else if c.field_name == 'A' {
			assert v is i32 && v == 100
		} else if c.field_name == 'B' {
			assert v is string && v == 'this is a varchar field'
		} else if c.field_name == 'D' {
			assert v is string && v == 'this is a blob field'
		} else {
			assert v is firebird.Null
		}
	}

	values = rows[4].values()
	for i := 0; i < values.len; i++ {
		c := result.columns()[i]
		v := values[i]
		if c.field_name == 'ID' {
			assert v is i32 && v == 5
		} else if c.field_name == 'A' {
			assert v is i32 && v == 1000
		} else if c.field_name == 'E' {
			assert v is f64 && v == f64(6.02214)
		} else if c.field_name == 'F' {
			assert v is f32 && v == f32(3.14)
		} else {
			assert v is firebird.Null
		}
	}

	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

fn test_char_boolean() {
	mut conn := firebird.new_connection(firebird_url)!
	mut tx := start_transaction(mut conn)!
	tx.execute('CREATE TABLE foo (
		id CHAR(3) PRIMARY KEY NOT NULL,
		includes_tax BOOLEAN DEFAULT true
		)')!
	tx.commit()!

	id := 'EUR'

	tx = start_transaction(mut conn)!
	tx.execute('INSERT INTO foo (id) VALUES (?)', id)!
	mut r := tx.execute('SELECT id, includes_tax FROM foo WHERE id = ?', id)!

	assert r.rows().len == 1
	mut v, mut v_is_null := r.rows()[0].values()[1].get_bool()!
	assert v == true

	tx.execute('UPDATE foo SET includes_tax = ? WHERE id = ?', false, id)!
	r = tx.execute('SELECT id, includes_tax FROM foo WHERE id = ?', id)!
	v, v_is_null = r.rows()[0].values()[1].get_bool()!
	assert v == false

	tx.execute('UPDATE foo SET includes_tax = ? WHERE id = ?', true, id)!
	r = tx.execute('SELECT id, includes_tax FROM foo WHERE id = ?', id)!
	v, v_is_null = r.rows()[0].values()[1].get_bool()!
	assert v == true

	tx.execute('UPDATE foo SET includes_tax = ? WHERE id = ?', firebird.Null{}, id)!
	r = tx.execute('SELECT id, includes_tax FROM foo WHERE id = ?', id)!
	v, v_is_null = r.rows()[0].values()[1].get_bool()!
	assert v == false
	assert v_is_null == true
	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!

	conn.close()!
}

