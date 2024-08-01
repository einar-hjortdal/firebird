module firebird

const lib := 'firebird'

fn new_error(message) ! {
	return error(format_error_message('[${lib}] ${message}'))
}