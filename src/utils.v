module firebird

import arrays
import encoding.binary
import encoding.hex
import log
import math.big
import os

const lib = 'firebird'
const mask_byte = u8(0b1111_1111)

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

// WireProtocol
// https://www.ietf.org/rfc/rfc4506.html#section-4.1
fn marshal_i32_big_endian(n i32) []u8 {
	return [
		u8((n >> 24) & mask_byte),
		u8((n >> 16) & mask_byte),
		u8((n >> 8) & mask_byte),
		u8(n & mask_byte),
	]
}

fn marshal_i32_small_endian(n i32) []u8 {
	return [
		u8(n & mask_byte),
		u8((n >> 8) & mask_byte),
		u8((n >> 16) & mask_byte),
		u8((n >> 24) & mask_byte),
	]
}

// `create_bytes` returns the array `a` prefixed by the length of the array.
// It also returns the number of bytes to pad to align the array to multiples of 4 bytes.
fn create_bytes(a []u8) ([]u8, int) {
	len := i32(a.len)
	marshalled_len := marshal_i32_big_endian(len)
	res := arrays.append(marshalled_len, a)
	bytes_to_pad := 4 - (len % 4)
	return res, bytes_to_pad
}

// https://www.ietf.org/rfc/rfc4506.html#section-4.11
fn marshal_string(s string) []u8 {
	a := s.bytes()
	mut res, bytes_to_pad := create_bytes(a)
	return arrays.append(res, []u8{len: bytes_to_pad})
}

// https://www.ietf.org/rfc/rfc4506.html#section-4.13
fn marshal_bytes(a []u8) []u8 {
	mut res, bytes_to_pad := create_bytes(a)
	if bytes_to_pad == 4 {
		return res
	}
	return arrays.append(res, []u8{len: bytes_to_pad})
}

fn parse_i32(b []u8) i32 {
	return i32(binary.big_endian_u32(b))
}

fn parse_i16(b []u8) i16 {
	return i16(binary.little_endian_u16(b))
}

// Returns the executable file path, limiting the path to 255 characters.
fn get_executable() string {
	e := os.executable()
	len := e.len
	if len > 255 {
		return e[len - 255..]
	}
	return e
}

fn attach_append_auth_data(a []u8, auth_data []u8) []u8 {
	if auth_data.len == 0 {
		return a
	}
	specific_auth_data_bytes := hex.encode(auth_data).bytes()
	dpb_specific_auth_data := arrays.append([u8(isc_dpb_specific_auth_data),
		u8(specific_auth_data_bytes.len)], specific_auth_data_bytes)
	return arrays.append(a, dpb_specific_auth_data)
}

fn attach_append_timezone(a []u8, timezone string) []u8 {
	if timezone == '' {
		return a
	}
	timezone_bytes := timezone.bytes()
	dpb_session_time_zone := arrays.append([u8(isc_dpb_session_time_zone), u8(timezone_bytes.len)],
		timezone_bytes)
	return arrays.append(a, dpb_session_time_zone)
}

fn get_system_user() []u8 {
	system_user := os.getenv('USER')
	if system_user == '' {
		return os.getenv('USERNAME').bytes()
	}
	return system_user.bytes()
}

fn get_hostname() []u8 {
	hostname := os.hostname() or { return []u8{} }
	return hostname.bytes()
}

fn get_wire_crypt_u8(wire_crypt bool) u8 {
	if wire_crypt == true {
		return u8(1)
	}
	return u8(0)
}

fn get_srp_client_public_key_bytes(client_public_key big.Integer) []u8 {
	b := client_public_key.hex().bytes()
	len := b.len
	if len > 254 {
		mut res := [u8(cnct_specific_data), 255, 0]
		res = arrays.append(res, b[..254])
		res = arrays.append(res, [u8(cnct_specific_data), u8((len - 254) + 1), 1])
		res = arrays.append(res, b[254..])
		return res
	}

	return arrays.append([u8(cnct_specific_data), u8(len) + 1, 0], b)
}

fn get_specific_data(auth_plugin_name string, client_public_key big.Integer) []u8 {
	if auth_plugin_name == 'Srp' || auth_plugin_name == 'Srp256' {
		return get_srp_client_public_key_bytes(client_public_key)
	}

	if auth_plugin_name == 'Legacy_Auth' {
		panic(format_error_message(legacy_auth_error))
	}
	panic(format_error_message('Unknown plugin name: ${auth_plugin_name}'))
}

fn user_identification(user string, auth_plugin_name string, wire_crypt bool, client_public_key big.Integer) []u8 {
	user_name_bytes := user.to_upper().bytes()
	user_name := arrays.append([u8(cnct_login), u8(user_name_bytes.len)], user_name_bytes)

	plugin_name_bytes := auth_plugin_name.bytes()
	plugin_name := arrays.append([u8(cnct_plugin_name), u8(plugin_name_bytes.len)], plugin_name_bytes)

	plugin_list_bytes := plugin_list.bytes()
	plugins := arrays.append([u8(cnct_plugin_list), u8(plugin_list_bytes.len)], plugin_list_bytes)

	specific_data := get_specific_data(auth_plugin_name, client_public_key)

	wire_crypt_byte := get_wire_crypt_u8(wire_crypt)
	wire_crypt_bytes := [u8(cnct_client_crypt), 4, wire_crypt_byte, 0, 0, 0]

	system_user_bytes := get_system_user()
	system_user := arrays.append([u8(cnct_user), u8(system_user_bytes.len)], system_user_bytes)

	hostname_bytes := get_hostname()
	hostname := arrays.append([u8(cnct_host), u8(hostname_bytes.len)], hostname_bytes)

	verification := [u8(cnct_user_verification), 0]

	mut res := arrays.append(user_name, plugin_name)
	res = arrays.append(res, plugins)
	res = arrays.append(res, specific_data)
	res = arrays.append(res, wire_crypt_bytes)
	res = arrays.append(res, system_user)
	res = arrays.append(res, hostname)
	res = arrays.append(res, verification)
	return res
}

fn received_packets_padding(n int) int {
	remainder := n % 4
	if remainder > 0 {
		return 4 - remainder
	}
	return remainder
}

fn (mut p WireProtocol) receive_aligned_packets(n i32) ![]u8 {
	if n == 0 {
		return []u8{}
	}

	padding := received_packets_padding(n)
	buf := p.receive_packets(n + padding)!
	res := buf[..n] // exclude padding
	return res
}

fn get_wire_crypt_from_options(o map[string]string) bool {
	if 'wire_crypt' in o {
		return parse_bool(o['wire_crypt'])
	}
	return true
}
