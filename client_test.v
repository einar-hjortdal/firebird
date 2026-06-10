module firebird

import time
import internal.test_utils

fn testsuite_begin() ! {
	test_utils.container_firebird_start()!
}

fn testsuite_end() ! {
	test_utils.container_firebird_clean()
}

fn start_client() !&Client {
	c := new_client(ClientConfig{
		url: test_utils.firebird_url
	})!
	time.sleep(time.second * 3) // wait for connections to be opened and appended to c.connections
	// TODO if the application attempts to perform database operations while the client is starting, an unnecessary number of connections may be opened. There should be a startup-lock or another mechanism to prevent that from happening.
	return c
}

fn start_transaction(mut c Client) !&ClientTransaction {
	return c.start_transaction(isolation_level_read_commited)
}

fn test_rollback() {
	mut c := start_client()!
	mut tx := start_transaction(mut c)!
	assert c.connections_length == default_min_pool_size
	assert c.connections.len == default_min_pool_size
	assert c.idle_connections.len == default_min_pool_size - 1

	tx.rollback()!
	assert c.connections_length == default_min_pool_size
	assert c.connections.len == default_min_pool_size
	assert c.idle_connections.len == default_min_pool_size

	c.close()
	assert c.is_closed
}
