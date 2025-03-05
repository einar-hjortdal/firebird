module firebird

const protocol = 'firebird://'
const user = 'fbusr'
const password = 'fbpwd'
const host = '127.0.0.1:3050'
const database = '/var/lib/firebird/data/firebird.fdb'
const url = '${protocol}${user}:${password}@${host}${database}'

fn test_open_no_db() {
	mut conn := open('${protocol}${user}@${host}') or {
		assert true // protocol error: no database is provided
		return
	}
	conn.close() or { panic(err) }
}

// Verifies that the protocol is added if not provided.
fn test_open_no_protocol() {
	mut conn := open('${user}:${password}@${host}${database}') or {
		panic(err)
		// TODO BLOCKING
		// V panic: [firebird] Your user name and password are not defined. Ask your database administrator to set up a Firebird login.
		// Seems like an SRP issue: if giving wrong user, it fails before op_cont_auth
	}
	conn.close() or { panic(err) }
}

fn test_open() {
	println('test started')
	mut conn := open(url) or { panic(err) }
	conn.close() or { panic(err) }
}
