module tests

import internal.test_utils
import einar_hjortdal.luuid

fn testsuite_begin() ! {
	test_utils.container_firebird_start()
}

fn testsuite_end() ! {
	test_utils.container_firebird_clean()
}

fn test_luuid() {
	mut gen := luuid.new_generator()
	id := gen.v1()
	id_bin := luuid.to_bytes(id)!

	mut conn := new_connection()!

	mut tx := start_transaction(mut conn)!
	tx.execute('CREATE TABLE foo (
		id BINARY(16) PRIMARY KEY NOT NULL,
		a BINARY(16)
		)')!
	tx.commit()!

	tx = start_transaction(mut conn)!

	// This query inserts id using CHAT_TO_UUID in the column id, and id as []u8 in the column a
	tx.execute('INSERT INTO foo (id, a) VALUES (CHAR_TO_UUID(?), ?)', id, id_bin)!

	// The following query will prove that firebirds stores id and a identically
	res := tx.execute('SELECT UUID_TO_CHAR(id), a FROM foo WHERE id = a')!
	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!

	conn.close()!

	// If the value in both columns is the same, we expect one row of results.
	assert res.rows.len == 1

	// Now the row values are converted and compared at the app level
	got_id, _ := res.rows[0].values[0].get_string()!
	a_bin, _ := res.rows[0].values[1].get_array_u8()!
	got_a := luuid.from_bytes(a_bin)!

	// got_id contains whitespaces that needs to be trimmed.
	// Don't know why this happens. got.id.len == 144, 4 times 36.
	// The firebird server sends this array as text with utf8 encoding
	// [48, 54, 56, 50, 52, 53, 53, 70, 45, 55, 50, 49, 52, 45, 49, 66, 52, 66, 45, 51, 67, 48, 48, 45, 55, 49, 68, 66, 69, 57, 69, 57, 65, 69, 48, 67, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32]
	// All those 32 after the id make no sense to me.
	//
	// got_a needs to be normalized to uppercase because firebird always normalizes to uppercase.
	assert got_id.trim_space() == got_a.to_upper()
}
