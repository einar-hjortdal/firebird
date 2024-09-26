module firebird

import arrays
import log
import math.big
import os

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

fn big_integer_to_byte_array(b big.Integer) []u8 {
	byte_array, _ := b.bytes()
	return byte_array
}

// appends any number of arrays arrs to the array a
fn append[T](a []T, arrs ...[]T) []T {
	mut res := []T{}
	res = arrays.append(res, a)
	for arr in arrs {
		res = arrays.append(res, arr)
	}
	return res
}

// parse_bool returns true if the string represents a true bool, or false otherwise.
// Any of the following are accepted as true values: 1, t, T, TRUE, true, True.
fn parse_bool(s string) bool {
	string_true := ['1', 't', 'T', 'TRUE', 'true', 'True']
	for value in string_true {
		if s == value {
			return true
		}
	}
	return false
}
