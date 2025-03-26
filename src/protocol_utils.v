module firebird

import arrays
import encoding.binary
import encoding.hex
import math
import math.big
import os
import strings

const zero_byte = u8(0)
const mask_byte = u8(0b1111_1111)
const chacha20_32 = 'ChaCha'
const chacha20_64 = 'ChaCha64'
const zero_terminated_chacha20_32 = arrays.concat(chacha20_32.bytes(), zero_byte)
const zero_terminated_chacha20_64 = arrays.concat(chacha20_64.bytes(), zero_byte)

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/src/main/org/firebirdsql/gds/impl/wire/WireProtocolConstants.java#L168
const fb_protocol_flag = i32(0b0000_0000_0000_0000_1000_0000_0000_0000)

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-attach-identification
fn build_protocol(protocol_version i32, architecture_type i32, minimum_type i32, maximum_type i32, preference_weight i32) []u8 {
	mut res := []u8{}
	res = arrays.append(res, marshal_i32_big_endian(fb_protocol_flag | protocol_version))
	res = arrays.append(res, marshal_i32_big_endian(architecture_type))
	res = arrays.append(res, marshal_i32_big_endian(minimum_type))
	res = arrays.append(res, marshal_i32_big_endian(maximum_type))
	res = arrays.append(res, marshal_i32_big_endian(preference_weight))
	return res
}

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/src/main/org/firebirdsql/gds/impl/wire/WireProtocolConstants.java#L183
const protocol_version_18 = build_protocol(18, 1, 0, 5, 20)

const supported_protocols = [protocol_version_18]

const supported_protocols_count = i32(supported_protocols.len)

fn supported_protocols_to_bytes() []u8 {
	mut res := []u8{}
	for p in supported_protocols {
		res = arrays.append(res, p)
	}
	return res
}

const supported_protocols_bytes = supported_protocols_to_bytes()

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

fn marshal_bytes(a []u8) []u8 {
	mut res, bytes_to_pad := create_bytes(a)
	if bytes_to_pad == 4 {
		return res
	}
	return arrays.append(res, []u8{len: bytes_to_pad})
}

fn marshal_string(s string) []u8 {
	return marshal_bytes(s.bytes())
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

fn get_wire_crypt_from_options(o map[string]string) bool {
	if 'wire_crypt' in o {
		return parse_bool(o['wire_crypt'])
	}
	return true
}

fn parse_wire_crypt_buffer(buf []u8) (string, []string, [][]u8) {
	mut encryption_type := ''
	mut available_plugins := []string{}
	mut plugin_nonces := [][]u8{}
	mut b := 0
	for b < buf.len {
		type_of_data := buf[b]
		b += 1
		length := buf[b]
		b += 1
		v := buf[b..b + length]
		b += length
		if type_of_data == 0 {
			encryption_type = v.bytestr()
		}
		if type_of_data == 1 {
			available_plugins = v.bytestr().split(' ')
		}
		if type_of_data == 3 {
			plugin_nonces = arrays.append(plugin_nonces, [v])
		}
	}
	return encryption_type, available_plugins, plugin_nonces
}

fn choose_wire_crypt(buf []u8) !(string, []u8) {
	_, available_plugins, plugin_nonces := parse_wire_crypt_buffer(buf)

	for nonce in plugin_nonces {
		if nonce[..9] == zero_terminated_chacha20_64 {
			// return chacha20_64, nonce[9..]
		}
	}

	for nonce in plugin_nonces {
		if nonce[..7] == zero_terminated_chacha20_32 {
			return chacha20_32, nonce[7..nonce.len - 4] // this one specifically is terminated by 4 zeros, I don't know why
		}
	}

	if available_plugins.contains('Arc4') {
		return 'Arc4', []u8{}
	}

	return error(format_error_message('Unsupported crypt plugin'))
}

fn initialize_blr_data(params []Value) strings.Builder {
	param_count := params.len * 2
	mut b := strings.new_builder(6)
	b.write_u8(blr_version5)
	b.write_u8(blr_begin)
	b.write_u8(blr_message)
	b.write_u8(0)
	b.write_u8(u8(param_count & mask_byte))
	b.write_u8(u8(param_count >> 8))
	return b
}

fn initialize_values_data(params []Value) strings.Builder {
	// TODO link source
	mut b := strings.new_builder(0)
	big256 := big.integer_from_i64(256)
	mut null_indicator := big.integer_from_i64(0)
	for i := params.len - 1; i >= 0; i-- {
		if params[i] is Null {
			null_indicator.set_bit(u32(i), true)
		}
	}
	mut n := params.len / 8
	if params.len % 8 != 0 {
		n++
	}
	if n % 4 != 0 { // padding
		n += 4 - n % 4
	}
	for i := 0; i < n; i++ {
		mod_res := null_indicator % big256
		b.write_u8(u8(mod_res.int()))
		null_indicator = null_indicator / big256
	}
	return b
}

fn bytes_to_blr(v []u8) ([]u8, []u8) {
	n := v.len
	padding := []u8{len: (4 - n) & 3}
	value := arrays.append(v, padding)
	blr := [u8(blr_text), u8(n & 255), u8(n >> 8)]
	return blr, value
}

fn i32_to_blr(n i32) ([]u8, []u8) {
	value := marshal_i32_big_endian(n)
	blr := [u8(blr_long), 0]
	return blr, value
}

fn f64_to_blr(f f64) ([]u8, []u8) {
	value := binary.big_endian_get_u64(math.f64_bits(f))
	blr := [u8(blr_double)]
	return blr, value
}
