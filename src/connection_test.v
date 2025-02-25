module firebird

const test_url = 'firebird://fbusr:fbpwd@127.0.0.1:3050/var/lib/firebird/data/firebird.fdb'

fn test_new_connection() ! {
	mut conn := open(test_url)!
	conn.close()!
}
