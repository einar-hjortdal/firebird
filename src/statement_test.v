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

fn test_execute_statement() {
	mut conn := new_connection(tests.url)!
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	mut stmt := tx.prepare_statement('CREATE TABLE foo (a INTEGER)')!
	r := stmt.execute(no_args)!
	println(r)
	stmt.close()!
	tx.rollback()!
	conn.close()!
}

// fn test_result_without_data() {
// }

// fn test_result_with_data() {
// }
