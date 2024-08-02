module firebird

import log
import os

const lib = 'firebird'

fn format_error_message(message string) string {
	return '[${firebird.lib}] ${message}'
}

fn new_error(message string) ! {
	return error(format_error_message(message))
}

fn new_logger() log.Log {
	mut new_log := log.Log{}
	get_log_level := fn () log.Level {
		level_string := os.getenv('LOG_LEVEL')
		if level_string == '' {
			return log.Level.disabled
		}
		level := log.Level.from(level_string) or { return log.Level.disabled }
		return level
	}

	level := get_log_level()
	new_log.set_level(level)
	new_log.set_output_label(firebird.lib)
	return new_log
}

const logger = new_logger()
const is_debug = logger.get_level() == log.Level.debug
