module firebird

const protocol = 'firebird://'
const user = 'fbusr'
const password = 'fbpwd'
const host = '127.0.0.1:3050'
const database = '/var/lib/firebird/data/firebird.fdb'
const url = '${protocol}${user}:${password}@${host}${database}'

fn test_new_transaction() {
	mut conn := new_connection(url) or { panic(err) }
	mut tx := conn.start_transaction(isolation_level_read_commited)!
	tx.rollback()!
	conn.close() or { panic(err) }
}
