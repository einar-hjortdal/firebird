module test_utils

import os
import time

const firebird_container_name = 'test_firebird_server'
const firebird_port = '3051'
const firebird_user = 'test_user'
const firebird_root_password = 'test_root_password'
const firebird_password = 'test_password'
const firebird_database = 'test_database.fdb'
const firebird_database_path = '/var/lib/firebird/data/${firebird_database}'
const firebird_url = 'firebird://${firebird_user}:${firebird_password}@localhost:${firebird_port}${firebird_database_path}'

// Remember to `sudo usermod -aG docker $USER`
fn container_firebird_clean() {
	result := os.execute('docker stop ${firebird_container_name}')
	if result.exit_code != 0 {
		if result.output.contains('No such container') {
			return
		}
		eprintln(result.output)
	}
}

fn container_is_ready() {
	mut firebird_is_loading := true
	for firebird_is_loading {
		check :=
			os.execute('echo "SELECT \'ALIVE\' FROM RDB\\\$DATABASE; quit;" | docker exec -i ${firebird_container_name} isql localhost:${firebird_database_path} -user ${firebird_user} -password ${firebird_password} -q')
		if check.output.contains('ALIVE') {
			firebird_is_loading = false
		}
		time.sleep(1 * time.second)
	}
	return
}

fn container_firebird_start() ! {
	container_firebird_clean() // kill container if already running
	result :=
		os.execute('docker run --rm --detach --name=${firebird_container_name} --env=FIREBIRD_ROOT_PASSWORD=${firebird_root_password} --env=FIREBIRD_USER=${firebird_user} --env=FIREBIRD_PASSWORD=${firebird_password} --env=FIREBIRD_DATABASE=${firebird_database} --env=FIREBIRD_DATABASE_DEFAULT_CHARSET=UTF8 --publish=${firebird_port}:3050 firebirdsql/firebird')
	if result.exit_code != 0 {
		return error(result.output)
	}
	container_is_ready()
}
