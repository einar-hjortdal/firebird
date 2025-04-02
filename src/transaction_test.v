module firebird

import tests

fn test_new_transaction() {
	mut conn := new_connection(tests.url) or { panic(err) }
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.rollback()!
	conn.close() or { panic(err) }
}

fn test_commit() {
}
