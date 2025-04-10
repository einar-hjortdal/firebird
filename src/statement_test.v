module firebird

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
const no_args = []Value{}

// TODO cleanup functions: ensure manual intervention is never needed.

// fn test_open_no_db() {
// 	mut conn := new_connection('${protocol}${user}@${host}') or {
// 		assert true // protocol error: no database is provided
// 		return
// 	}
// 	conn.close() or { panic(err) }
// }

// fn test_open_() {
// 	mut conn := new_connection(url) or { panic(err) }
// 	conn.close() or { panic(err) }
// }

// fn test_new_statement() {
// 	mut conn := new_connection(url)!
// 	mut tx := conn.start_transaction(isolation_level_read_commited)!

// 	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
// 	stmt.close()!

// 	tx.rollback()!
// 	conn.close()!
// }

// fn test_execute_statement_ddl_no_args() {
// 	mut conn := new_connection(url)!
// 	mut tx := conn.start_transaction(isolation_level_read_commited)!

// 	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
// 	stmt.execute(no_args)!
// 	stmt.execute(no_args) or {
// 		// [firebird] unsuccessful metadata update
// 		// CREATE TABLE FOO failed
// 		// Table FOO already exists
// 		assert err.msg().contains('Table FOO already exists')
// 	}
// 	stmt.close()!

// 	stmt = tx.prepare_statement('DROP TABLE foo')!
// 	stmt.execute(no_args)!
// 	stmt.execute(no_args) or {
// 		// [firebird] unsuccessful metadata update
// 		// DROP TABLE FOO failed
// 		// SQL error code = -607
// 		// Invalid command
// 		// Table FOO does not exist
// 		assert err.msg().contains('Table FOO does not exist')
// 	}
// 	stmt.close()!

// 	tx.rollback()!
// 	conn.close()!
// }

fn test_execute_select() {
	mut conn := new_connection(url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement('SELECT current_timestamp FROM RDB\$DATABASE')!
	stmt.execute(no_args)!
	tx.rollback()!
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
			h BLOB SUB_TYPE 1,
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

	stmt = tx.prepare_statement('SELECT a, b, c, h FROM foo')!
	result := stmt.execute(no_args)!

	rows := result.rows()
	row := rows[0].values()

	a_value := row[0]
	assert a_value is i32 && a_value == 1

	b_value := row[1]
	assert b_value is string && b_value == 'a'

	c_value := row[2]
	assert c_value is string && c_value == 'b'

	stmt.close()!

	stmt = tx.prepare_statement('DROP TABLE foo')!
	stmt.execute(no_args)!
	stmt.close()!

	tx.commit()!
	conn.close()!
}

// fn test_execute_statement_with_args() {
// }
