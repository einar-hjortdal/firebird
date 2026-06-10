module tests

import firebird
import test_utils

fn testsuite_begin() ! {
	test_utils.container_firebird_start()!
}

fn testsuite_end() ! {
	test_utils.container_firebird_clean()
}

fn test_open_no_db() {
	mut conn := firebird.new_connection('firebird://${test_utils.firebird_user}:${test_utils.firebird_password}@localhost') or {
		assert true // protocol error: no database is provided
		return
	}
	conn.close()!
}

fn test_open() {
	mut conn := new_connection()!
	conn.close()!
}
