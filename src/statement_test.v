module firebird

import tests

fn test_new_statement() {
	mut conn := new_connection(tests.url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	stmt.close()!
	println(stmt.tx.conn.p.lazy_response_count) // 1
	println(tx.conn.p.lazy_response_count) // 0
	// Despite all structs being `mut`. Why is this happening?
	tx.rollback()!
	conn.close()!
}

fn test_execute_statement() {
}

fn test_result_without_data() {
}

fn test_result_with_data() {
}
