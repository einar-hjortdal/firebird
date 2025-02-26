module firebird

const protocol = 'firebird://'
const user = 'fbusr'
const password = 'fbpwd'
const host = '127.0.0.1:3050'
const database = '/var/lib/firebird/data/firebird.fdb'
const url = '${protocol}${user}:${password}@${host}${database}'

fn test_open_no_protocol() {
	mut conn := open('${user}:${password}@${host}${database}') or { panic(err) }
	conn.close() or { panic(err) }
}

fn test_open_no_db() {
	mut conn := open('${protocol}${user}@${host}') or {
		assert true // as expected, connection is rejected because no database is provided.
		return
	}
	conn.close() or { panic(err) }
}

fn test_open() {
	mut conn := open(url) or { panic(err) }
	conn.close() or { panic(err) }
}
