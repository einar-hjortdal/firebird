module tests

import firebird
import test_utils

fn new_connection() !&firebird.Connection {
	return firebird.new_connection(test_utils.firebird_url)!
}

fn start_transaction(mut conn firebird.Connection) !&firebird.Transaction {
	return conn.start_transaction(firebird.isolation_level_read_commited)
}

type Null = firebird.Null // https://github.com/vlang/v/issues/27402
