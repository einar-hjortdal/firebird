module firebird

import tests

fn test_new_statement() {
	mut conn := new_connection(tests.url) or { panic(err) }
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	stmt.close()!
	tx.rollback()!
	conn.close() or { panic(err) }
}

fn test_execute_statement() {
}
