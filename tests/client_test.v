module tests

import internal.test_utils
import firebird
import time

fn testsuite_begin() ! {
	test_utils.container_firebird_start()!
}

fn testsuite_end() ! {
	test_utils.container_firebird_clean()
}

fn start_client() !&firebird.Client {
	c := firebird.new_client(firebird.ClientConfig{
		url: test_utils.firebird_url
	})!
	time.sleep(time.second * 3) // wait for connections to be opened and appended to c.connections
	// TODO if the application attempts to perform database operations while the client is starting, an unnecessary number of connections may be opened. There should be a startup-lock or another mechanism to prevent that from happening.
	return c
}

fn start_client_transaction(mut c firebird.Client) !&firebird.ClientTransaction {
	return c.start_transaction(firebird.isolation_level_read_commited)
}

fn test_execute() {
	mut c := start_client()!
	mut tx := start_client_transaction(mut c)!
	tx.execute('CREATE TABLE foo (a INTEGER)')!
	tx.commit()!

	tx = start_client_transaction(mut c)!
	tx.execute('INSERT INTO foo (a) VALUES (?)', i32(200))!
	data := tx.execute('SELECT a FROM foo')!
	rows := data.rows()
	assert rows.len == 1
	values := rows[0].values()
	assert values.len == 1
	a, _ := values[0].get_i32()!
	assert a == 200
	tx.execute('DROP TABLE foo')!
	tx.commit()!

	c.close()
}
