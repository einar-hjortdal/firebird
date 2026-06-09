module tests

import firebird

fn testsuite_begin() ! {
	container_firebird_start()!
	container_is_ready()
}

fn testsuite_end() ! {
	container_firebird_clean()
}

fn test_new_client() {
	client := firebird.new_client(firebird.ClientConfig{
		url: firebird_url
	})!
	client.close()
}

