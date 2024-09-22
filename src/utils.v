module firebird

import log
import os
import crypto.rand

const lib = 'firebird'

fn format_error_message(message string) string {
	return '[${lib}] ${message}'
}

fn format_op_error(op_error_code i32) string {
	return format_error_message('Error: op_response ${op_error_code}')
}

fn get_log_level() log.Level {
	level_string := os.getenv('LOG_LEVEL')
	if level_string == '' {
		return log.Level.disabled
	}
	level := log.level_from_tag(level_string) or { return log.Level.disabled }
	return level
}

fn new_logger() log.Log {
	mut new_log := log.Log{}
	level := get_log_level()
	new_log.set_level(level)
	new_log.set_output_label(lib)
	return new_log
}

fn is_debug() bool {
	level := get_log_level()
	if level == log.Level.debug {
		return true
	}
	return false
}

fn random_u8() !u8 {
	a := rand.read(1)!
	return a[0]
}