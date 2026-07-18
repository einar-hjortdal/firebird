module tests

import firebird
import internal.test_utils

fn new_connection() !&firebird.Connection {
	return firebird.new_connection(test_utils.firebird_url)!
}

fn start_transaction(mut conn firebird.Connection) !&firebird.ConnectionTransaction {
	return conn.start_transaction(firebird.isolation_level_read_commited)
}
