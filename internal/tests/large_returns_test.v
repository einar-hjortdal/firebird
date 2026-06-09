module tests

import rand
import firebird

fn testsuite_begin() ! {
	container_firebird_start()!
	container_is_ready()
}

fn testsuite_end() ! {
	container_firebird_clean()
}

fn test_large_returns() {
	rows_number := 500
	last_row_index := rows_number - 1
	mut conn := firebird.new_connection(firebird_url)!

	mut tx := start_transaction(mut conn)!
	tx.execute('CREATE TABLE foo (
		id BINARY(16) NOT NULL PRIMARY KEY,
		code VARCHAR(63) NOT NULL UNIQUE
		)')!
	tx.commit()!

	tx = start_transaction(mut conn)!
	mut stmt := tx.prepare('INSERT INTO foo (id, code) VALUES (?, ?)')!
	mut expected_last_code := ''
	for i := 0; i < rows_number; i++ {
		id := rand.bytes(16)!
		code := rand.ascii(63)
		stmt.execute(id, code)!
		if i == last_row_index { expected_last_code = code }
	}
	stmt.close()!
	tx.commit()!

	tx = start_transaction(mut conn)!
	result := tx.execute('SELECT id, code FROM foo')!
	tx.rollback()!

	rows := result.rows()
	assert rows.len == rows_number
	last_row := rows[last_row_index].values()
	last_code, _ := last_row[1].get_string()!
	assert last_code == expected_last_code

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

