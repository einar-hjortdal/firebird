module firebird

import crypto.rand
import log
import math.big
import os

const lib = 'firebird'

fn format_error_message(message string) string {
	return '[${lib}] ${message}'
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
	new_log.set_output_label(lib)
	return new_log
}

const logger = new_logger()
const is_debug = logger.get_level() == log.Level.debug

// new_random_big_integer creates a random `big.Integer` with range [0, n)
// panics if `n` is 0 or negative.
// https://github.com/vlang/v/issues/22206
pub fn new_random_big_integer(n big.Integer) !big.Integer {
	if n.signum < 1 {
		return error('`n` cannot be 0 or negative.')
	}

	max := n - big.integer_from_int(1)
	len := max.bit_len()

	if len == 0 {
		// max must be 0
		return max
	}

	// k is the maximum byte length needed to encode a value < n
	k := (len + 7) / 8

	// b is the number of bits in the most significant byte of n-1
	get_b := fn [len] () u64 {
		b := u64(len % 8)
		if b == 0 {
			return 8
		}
		return b
	}
	b := get_b()

	mut result := big.Integer{}
	for found := false; found == false; {
		mut bytes := rand.read(k)!

		// Clear bits in the first byte to increase the probability that the candidate is < max
		bytes[0] &= u8(int(1 << b) - 1)

		result = big.integer_from_bytes(bytes)
		if result < max {
			found = true
		}
	}
	return result
}
