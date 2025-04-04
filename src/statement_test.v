module firebird

import tests

const no_args = []Value{}

// fn test_new_statement() {
// 	mut conn := new_connection(tests.url)!
// 	mut tx := conn.start_transaction(isolation_level_read_commited)!

// 	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
// 	stmt.close()!

// 	tx.rollback()!
// 	conn.close()!
// }

// test_execute_statement verifies that a statement can be executed
fn test_execute_statement_no_args() {
	mut conn := new_connection(tests.url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut stmt_create := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	stmt_create.execute(no_args)!
	stmt_create.execute(no_args) or {
		// [firebird] unsuccessful metadata update
		// CREATE TABLE FOO failed
		// Table FOO already exists
		assert err.msg().contains('Table FOO already exists')
	}
	stmt_create.close()!

	mut stmt_drop := tx.prepare_statement('DROP TABLE foo')!
	stmt_drop.execute(no_args)!
	stmt_drop.execute(no_args) or {
		// [firebird] unsuccessful metadata update
		// DROP TABLE FOO failed
		// SQL error code = -607
		// Invalid command
		// Table FOO does not exist
		assert err.msg().contains('Table FOO does not exist')
	}

	stmt_create = tx.prepare_statement("CREATE TABLE foo (
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
	stmt_create.execute(no_args)!
	stmt_create.close()!

	stmt_drop.execute(no_args)!
	stmt_drop.close()!

	tx.rollback()!
	conn.close()!
}

// fn test_result_without_data() {
// }

// fn test_result_with_data() {
// }
