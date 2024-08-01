module firebird

import arrays
import encoding.binary
import math.big
import net
import os
import strings

struct WireProtocol {
mut:
	buf []u8

	conn      WireChannel
	db_handle i32
	addr      string

	protocol_version    i32
	accept_architecture i32
	accept_type         i32
	lazy_response_count int

	plugin_name string
	user        string
	password    string
	auth_data   []u8

	charset          string
	charset_byte_len int

	timezone string
}

fn new_wire_protocol(addr string, timezone string) !&WireProtocol {
	conn := net.dial_tcp(addr)!
	return &WireProtocol{
		buf: []u8{}
		conn: new_wire_channel(conn)
		addr: addr
		charset: 'UTF8'
		charset_byte_len: 4
		timezone: timezone
	}
}

fn (mut p WireProtocol) pack_i32(i i32) {
	i32_bytes := marshal_i32(i)
	p.buf = arrays.append(p.buf, i32_bytes)
}

fn (mut p WireProtocol) pack_array_u8(au []u8) {
	array_u8_bytes := marshal_array_u8(au)
	p.buf = arrays.append(p.buf, array_u8_bytes)
}

fn (mut p WireProtocol) pack_string(s string) {
	string_bytes := marshal_array_u8(s.bytes())
	p.buf = arrays.append(p.buf, string_bytes)
}

fn (mut p WireProtocol) append_array_u8(au []u8) {
	p.buf = arrays.append(p.buf, au)
}

fn (mut p WireProtocol) user_identification(user string, auth_plugin_name string, wire_crypt bool, client_public big.Integer) []u8 {
	get_system_user := fn () []u8 {
		system_user := os.getenv('USER')
		if system_user == '' {
			return os.getenv('USERNAME').bytes()
		}
		return system_user.bytes()
	}

	get_hostname := fn () []u8 {
		hostname := os.hostname() or { '' }
		return hostname.bytes()
	}

	get_wire_crypt_u8 := fn [wire_crypt] () u8 {
		if wire_crypt == true {
			return u8(1)
		}
		return u8(0)
	}

	get_srp_client_public := fn [client_public] () []u8 {
		b, _ := client_public.bytes()
		len := b.len
		if len > 254 {
			mut res := [u8(cnct_specific_data), 255, 0]
			res = arrays.append(res, b[..254])
			res = arrays.append(res, [u8(cnct_specific_data), u8((len - 254) + 1), 1])
			res = arrays.append(res, b[254..])
			return res
		}

		return arrays.append([u8(cnct_specific_data), u8(len + 1), 0], b)
	}

	get_specific_data := fn [auth_plugin_name, get_srp_client_public] () []u8 {
		if auth_plugin_name == 'Srp' || auth_plugin_name == 'Srp256' {
			return get_srp_client_public()
		}

		if auth_plugin_name == 'Legacy_Auth' {
			panic(legacy_auth_error)
		}
		panic('Unknown plugin name: ${auth_plugin_name}')
	}

	user_name_bytes := user.to_upper().bytes()
	user_name := arrays.append([u8(cnct_login), u8(user_name_bytes.len)], user_name_bytes)

	plugin_name_bytes := auth_plugin_name.bytes()
	plugin_name := arrays.append([u8(cnct_plugin_name), u8(plugin_name_bytes.len)], plugin_name_bytes)

	plugins_bytes := plugin_list.bytes()
	plugins := arrays.append([u8(cnct_plugin_list), u8(plugins_bytes.len)], plugins_bytes)

	specific_data := get_specific_data()

	wire_crypt_byte := get_wire_crypt_u8()
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

fn (mut p WireProtocol) clear_buffer() {
	p.buf = []u8{}
}

fn (mut p WireProtocol) send_packets() !int {
	mut written := 0
	mut n := 0
	for written < p.buf.len {
		n = p.conn.write(p.buf[written..]) or { break }
		written += n
	}
	// p.conn.writer.flush()
	p.clear_buffer()
	return written
}

fn (mut p WireProtocol) suspend_buffer() []u8 {
	buf := p.buf
	p.clear_buffer()
	return buf
}

fn (mut p WireProtocol) resume_buffer(buf []u8) {
	p.buf = buf
}

fn (mut p WireProtocol) receive_packets(n int) ![]u8 {
	mut buf := []u8{}
	mut read := 0
	mut total_read := 0
	for total_read < n {
		read = p.conn.read(mut buf[total_read..n])!
		total_read += read
	}
	return buf
}

fn (mut p WireProtocol) receive_packets_alignment(n int) ![]u8 {
	get_padding := fn [n] () int {
		padding := n % 4
		if padding > 0 {
			return 4 - padding
		}
		return 0
	}
	padding := get_padding()

	buf := p.receive_packets(n + padding)!
	return buf[0..n]
}
