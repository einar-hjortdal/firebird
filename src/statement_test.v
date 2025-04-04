module firebird

import tests

const no_args = []Value{}

// To investigate manually:
// sudo docker run \
//   --rm \
//   -it \
//   --name=firebird-client \
//   --network=host \
//   firebirdsql/firebird \
//   isql -u fbusr -p fbpwd localhost:/var/lib/firebird/data/firebird.fdb

// fn test_new_statement() {
// 	mut conn := new_connection(tests.url)!
// 	mut tx := conn.start_transaction(isolation_level_read_commited)!

// 	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
// 	stmt.close()!

// 	tx.rollback()!
// 	conn.close()!
// }

// test_execute_statement verifies that a statement can be executed
fn test_execute_statement_ddl_no_args() {
	mut conn := new_connection(tests.url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!

	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	stmt.execute(no_args) or {
		tx.rollback()!
		panic(err)
	}
	stmt.execute(no_args) or {
		// [firebird] unsuccessful metadata update
		// CREATE TABLE FOO failed
		// Table FOO already exists
		assert err.msg().contains('Table FOO already exists')
	}
	stmt.close()!

	stmt = tx.prepare_statement('DROP TABLE foo')!
	stmt.execute(no_args) or {
		tx.rollback()!
		panic(err)
	}
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

fn test_execute_statement_dml_no_args() {
	mut conn := new_connection(tests.url)!
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

	mut cleanup_stmt := tx.prepare_statement('DROP TABLE foo')!
	stmt = tx.prepare_statement("
		INSERT INTO foo (a, b, c, h) 
			VALUES (1, 'a', 'b', 'This is a test')")!
	stmt.execute(no_args) or {
		// cleanup
		stmt.cleanup_stmt(no_args)!
		tx.commit()!
		conn.close()!
		panic(err)
	}
	stmt.execute(no_args) or {
		// [firebird] violation of PRIMARY or UNIQUE KEY constraint "INTEG_83" on table "FOO"
		// Problematic key value is ("B" = 'a')
		assert err.msg().contains('violation of PRIMARY or UNIQUE KEY constraint')
	}
	stmt.close()!

	cleanup_stmt.execute(no_args)!
	cleanup_stmt.close()!
	tx.commit()!
	conn.close()!
}

// fn test_execute_statement_with_args() {
// }

// fn test_result_without_data() {
// }

// fn test_result_with_data() {
// }
