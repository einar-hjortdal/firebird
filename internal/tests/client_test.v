module tests

import firebird

fn testsuite_begin() ! {
	container_firebird_start()!
	container_is_ready()
}

fn testsuite_end() ! {
	container_firebird_clean()
}
