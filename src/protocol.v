module firebird

import arrays
import encoding.binary
import math.big
import net
import os
// import strings

const buffer_length = i32(1024)

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
		buf:              []u8{}
		conn:             new_wire_channel(conn)
		addr:             addr
		charset:          'UTF8'
		charset_byte_len: 4
		timezone:         timezone
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
	// https://github.com/vlang/v/issues/22256#issuecomment-2366338836
	string_bytes_ := marshal_array_u8(s.bytes())
	p.buf = arrays.append(p.buf, string_bytes_)
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

fn (mut p WireProtocol) parse_status_vector() !([]int, int, string) {
	mut sql_code := 0
	mut gds_code := 0
	mut gds_codes := []int{}
	mut num_arg := 0
	mut message := ''

	mut b := p.receive_packets(4)!
	mut n := binary.big_endian_u16(b)
	for n != isc_arg_end {
		match n {
			isc_arg_gds {
				b = p.receive_packets(4)!
				gds_code = int(binary.big_endian_u16(b))
				if gds_code != 0 {
					gds_codes = arrays.concat(gds_codes, gds_code)
					msg := get_error_message(gds_code) or { err.msg() }
					message += msg
					num_arg = 0
				}
			}
			isc_arg_number {
				b = p.receive_packets(4)!
				num := int(binary.big_endian_u16(b))
				if gds_code == 335544436 {
					sql_code = num
				}
				num_arg++
				message = message.replace_once('@${num_arg}', '${num}')
			}
			isc_arg_string {
				b = p.receive_packets(4)!
				nbytes := int(binary.big_endian_u16(b))
				b = p.receive_packets_alignment(nbytes)!
				s := b.bytestr()
				num_arg++
				message = message.replace_once('@${num_arg}', s)
			}
			isc_arg_interpreted {
				b = p.receive_packets(4)!
				nbytes := int(binary.big_endian_u16(b))
				b = p.receive_packets_alignment(nbytes)!
				s := b.bytestr()
				message += s
			}
			isc_arg_sql_state {
				b = p.receive_packets(4)!
				nbytes := int(binary.big_endian_u16(b))
				b = p.receive_packets_alignment(nbytes)!
				_ := b.bytestr() // skip status code
			}
			else {}
		}
		b = p.receive_packets(4)!
		n = binary.big_endian_u16(b)
	}

	return gds_codes, sql_code, message
}

fn (mut p WireProtocol) parse_generic_response() !(i32, []u8, []u8) {
	b := p.receive_packets(16)!
	object_handle := i32(binary.big_endian_u16(b[..4]))
	object_id := b[4..12]
	response_buffer_length := i32(binary.big_endian_u16(b[12..]))
	response_buffer := p.receive_packets_alignment(response_buffer_length)!

	gds_code_list, sql_code, message := p.parse_status_vector()!
	if gds_code_list.len > 0 || sql_code != 0 {
		return error(format_error_message(message))
	}

	return object_handle, object_id, response_buffer
}

fn (mut p WireProtocol) guess_wire_crypt(buf []u8) (string, []u8) {
	mut params := map[u8][]u8{}
	for i := 0; i < buf.len; {
		k := buf[i]
		i++
		ln := buf[i]
		i++
		v := buf[i..i + ln]
		i += ln
		params[k] = v
	}

	if 3 in params {
		v := params[3]
		if (v[..7]).bytestr() == 'ChaCha\x00' {
			return 'ChaCha', v[7..v.len - 4]
		}
	}

	return 'Arc4', []u8{}
}

// https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-responses-generic
fn (mut p WireProtocol) generic_response() !(i32, []u8, []u8) {
	// logger.debug('generic_response')
	mut b := p.receive_packets(4)!

	for big_endian_i32(b) == op_dummy {
		b = p.receive_packets(4)!
	}

	for big_endian_i32(b) == op_crypt_key_callback {
		p.crypt_callback()!
		b = p.receive_packets(12)!
		b = p.receive_packets(4)!
	}

	for big_endian_i32(b) == op_response && p.lazy_response_count > 0 {
		p.lazy_response_count--
		p.parse_generic_response()!
		b = p.receive_packets(4)!
	}

	if big_endian_i32(b) != op_response {
		if is_debug() && big_endian_i32(b) == op_cont_auth {
			panic('auth error')
		}
		return error(format_op_error(big_endian_i32(b)))
	}
	return p.parse_generic_response()!
}

fn (mut p WireProtocol) parse_connect_response(user string, password string, options map[string]string, client_public big.Integer, client_secret big.Integer) ! {
	mut b := p.receive_packets(4)!
	mut opcode := big_endian_i32(b)

	for opcode == op_dummy {
		b = p.receive_packets(4) or { []u8{} }
		opcode = big_endian_i32(b)
	}

	if opcode == op_reject {
		return error(format_error_message('parse_connect_response op_reject'))
	}

	if opcode == op_response {
		p.parse_generic_response()! // error has occured
	}

	b = p.receive_packets(12) or { []u8{} }
	p.protocol_version = i32(b[3])
	p.accept_architecture = big_endian_i32(b[4..8])
	p.accept_type = big_endian_i32(b[8..12])

	if opcode == op_cond_accept || opcode == op_accept_data {
		b = p.receive_packets(12) or { []u8{} }
		mut ln := big_endian_i32(b)
		mut data := p.receive_packets_alignment(ln) or { []u8{} }

		b = p.receive_packets(4) or { []u8{} }
		ln = big_endian_i32(b)
		plugin_name := p.receive_packets_alignment(ln) or { []u8{} }
		p.plugin_name = plugin_name.bytestr()

		b = p.receive_packets(4) or { []u8{} }
		is_authenticated := big_endian_i32(b)

		b = p.receive_packets(4) or { []u8{} }
		ln = big_endian_i32(b)
		_ = p.receive_packets_alignment(ln) or { []u8{} } // keys

		mut auth_data := []u8{}
		mut session_key := []u8{}
		if is_authenticated == 0 {
			if p.plugin_name == 'Srp' || p.plugin_name == 'Srp256' {
				// TODO: normalize user

				if data.len == 0 {
					p.continue_authentication(pad(client_public), p.plugin_name, plugin_list,
						'')!
					b = p.receive_packets(4) or { []u8{} }
					op := big_endian_i32(b)
					if op == op_response {
						p.parse_generic_response()! // error occurred
					}

					if is_debug() && op != op_cont_auth {
						panic('auth error')
					}

					b = p.receive_packets(4) or { []u8{} }
					ln = big_endian_i32(b)
					data = p.receive_packets_alignment(ln) or { []u8{} }

					b = p.receive_packets(4) or { []u8{} }
					ln = big_endian_i32(b)
					p.receive_packets_alignment(ln) or { []u8{} } // plugin_name

					b = p.receive_packets(4) or { []u8{} }
					ln = big_endian_i32(b)
					p.receive_packets_alignment(ln) or { []u8{} } // plugin_list

					b = p.receive_packets(4) or { []u8{} }
					ln = big_endian_i32(b)
					p.receive_packets_alignment(ln) or { []u8{} } // keys
				}

				ln = big_endian_i16(data[..2])
				server_salt := data[2..ln + 2].clone()
				server_public := big.integer_from_string(data[4 + ln..].bytestr())!
				auth_data, session_key = get_client_proof(user.to_upper(), password, server_salt,
					client_public, server_public, client_secret, p.plugin_name)
				// logger.debug('plugin_name=${p.plugin_name}\nserver_salt=${server_salt}\nserver_public(bin)=${data[4 + ln..].bytestr()}\nserver_public=${server_public}\nauth_data=${auth_data},sessionKey=${session_key}\n')
			} else if p.plugin_name == 'Legacy_Auth' {
				return error(format_error_message(legacy_auth_error))
			} else {
				return error(format_error_message('parse_connect_response() Unauthorized'))
			}
		}

		get_encrypt_plugin_and_nonce := fn [mut p, opcode, auth_data, options] () !(string, []u8) {
			if opcode == op_cond_accept {
				p.continue_authentication(auth_data, options['auth_plugin_name'], plugin_list,
					'')!
				_, _, buf := p.generic_response() or { return '', []u8{} }
				return p.guess_wire_crypt(buf)
			}
			return error(format_error_message('received opcode ${opcode}, not ${op_cond_accept}'))
		}
		encrypt_plugin, nonce := get_encrypt_plugin_and_nonce()!

		mut wire_crypt := true
		wire_crypt = options['wire_crypt'].bool()
		if wire_crypt && session_key.len != 0 {
			// Send op_crypt
			p.crypt(encrypt_plugin)!
			p.conn.set_crypt_key(encrypt_plugin, session_key, nonce)!
			_, _, _ := p.generic_response() or { return }
		} else {
			p.auth_data = auth_data // use later opAttach and opCreate
		}
	} else {
		if opcode != op_accept {
			return error(format_error_message('parse_connect_response() protocol error'))
		}
	}

	return
}

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/remote/protocol.cpp#L794
fn (mut p WireProtocol) continue_authentication(auth_data []u8, auth_plugin_name string, auth_plugin_list string, keys string) ! {
	// logger.debug('continue_authentication')
	p.pack_i32(op_cont_auth)
	p.pack_string(auth_data.hex())
	p.pack_string(auth_plugin_name)
	p.pack_string(auth_plugin_list)
	p.pack_string(keys)
	p.send_packets()!
}

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/remote/protocol.cpp#L815
fn (mut p WireProtocol) crypt(plugin string) ! {
	p.pack_i32(op_crypt)
	p.pack_string(plugin)
	p.pack_string('Symmetric')
	p.send_packets()!
}

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/remote/protocol.cpp#L825
fn (mut p WireProtocol) crypt_callback() ! {
	// logger.debug('crypt_callback')
	p.pack_i32(op_crypt_key_callback)
	p.pack_i32(0)
	p.pack_i32(buffer_length)
	p.send_packets()!
}
