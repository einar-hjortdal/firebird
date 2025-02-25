module firebird

const test_url = 'firebird://fbusr:fbpwd@localhost:3050'

fn test_new_connection() {
	mut conn := open(test_url)!
	conn.close()!
}
