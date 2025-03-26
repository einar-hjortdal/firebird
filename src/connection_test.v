module firebird

import tests

fn test_open_no_db() {
	mut conn := new_connection('${tests.protocol}${tests.user}@${tests.host}') or {
		assert true // protocol error: no database is provided
		return
	}
	conn.close() or { panic(err) }
}

fn test_open_() {
	mut conn := new_connection(tests.url) or { panic(err) }
	conn.close() or { panic(err) }
}
