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

fn start_client_transaction(mut c Client) !&ClientTransaction {
	return c.start_transaction(isolation_level_read_commited)
}

fn test_rollback() {
	mut c := start_client()!
	mut tx := start_client_transaction(mut c)!
	assert c.connections.len == default_min_pool_size
	assert c.idle_connections.len == default_min_pool_size - 1

	tx.rollback()!
	assert c.connections.len == default_min_pool_size
	assert c.idle_connections.len == default_min_pool_size

	c.close()
	assert c.is_closed
}

fn test_connection_too_old_and_idle_too_long() {
	mut c := new_client(ClientConfig{
		url:                test_utils.firebird_url
		conn_max_life_time: time.millisecond * 50
		conn_max_idle_time: time.millisecond * 50
	})!

	mut conn := c.new_client_connection()!
	time.sleep(50 * time.millisecond)
	now := time.now()

	assert c.connection_is_too_old(mut conn, now)
	assert c.connection_waited_too_long(mut conn, now)

	c.close()
}

fn test_get_detects_closed_underlying_connection() {
	mut c := start_client()!

	mut conn_1 := c.get()!
	mut conn_2 := c.get()! // there should be 2, keep one busy while we work on the other.
	assert c.idle_connections.len == 0

	conn_1.fbconn.close()! // make conn_1 unhealthy
	c.put(mut conn_1)
	assert c.idle_connections.len == 1

	mut new_conn := c.get()! // should detect and remove the bad connection

	c.mutex.lock()
	for i := 0; i < c.connections.len; i++ {
		existing := c.connections[i]
		assert existing != conn_1
	}

	assert c.connections.len == c.min_pool_size
	assert c.idle_connections.len == 0
	c.mutex.unlock()

	c.put(mut conn_2)
	c.put(mut new_conn)
	c.close()
}
