module firebird

import arrays
import crypto.sha1
import encoding.binary
import encoding.hex
import math.big
import net
import os

const buffer_length = i32(1024)
const mask_1_byte = u8(0b1111_1111)

// https://www.ietf.org/rfc/rfc4506.html#section-4.1
fn marshal_i32(n i32) []u8 {
	return [
		u8((n >> 24) & mask_1_byte),
		u8((n >> 16) & mask_1_byte),
		u8((n >> 8) & mask_1_byte),
		u8(n & mask_1_byte),
	]
}

fn generate_padding(number_of_bytes i32) []u8 {
	mut res := []u8{}
	for i := 0; i < number_of_bytes; i++ {
		res = arrays.concat(res, u8(0))
	}
	return res
}

fn create_array_u8(a []u8) ([]u8, i32) {
	len := i32(a.len)
	marshalled_len := marshal_i32(len)
	res := arrays.append(marshalled_len, a)
	bytes_to_pad := 4 - (len % 4)
	return res, bytes_to_pad
}

// https://www.ietf.org/rfc/rfc4506.html#section-4.13
fn marshal_array_u8(a []u8) []u8 {
	mut res, bytes_to_pad := create_array_u8(a)
	if bytes_to_pad == 0 {
		return res
	}
	padding := generate_padding(bytes_to_pad)
	return arrays.append(res, padding)
}

// https://www.ietf.org/rfc/rfc4506.html#section-4.11
fn marshal_string(s string) []u8 {
	a := s.bytes()
	mut res, bytes_to_pad := create_array_u8(a)
	if bytes_to_pad == 0 {
		padding := generate_padding(4)
		return arrays.append(res, padding)
	}
	padding := generate_padding(bytes_to_pad)
	return arrays.append(res, padding)
}

fn big_int_to_sha1(n big.Integer) []u8 {
	mut digest := sha1.new()
	n_bytes, _ := n.bytes()
	digest.write(n_bytes) or { panic(err) }
	return sha1.sum([]u8{})
}

fn big_endian_i32(b []u8) i32 {
	return i32(binary.big_endian_u32(b))
}

fn big_endian_i16(b []u8) i16 {
	return i16(binary.big_endian_u16(b))
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

// The Firebird wire protocol uses XDR for exchange messages between client and server
// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-appendix-xdr
// https://www.ietf.org/rfc/rfc4506.html

fn (mut p WireProtocol) pack_i32(i i32) {
	i32_bytes := marshal_i32(i)
	p.buf = arrays.append(p.buf, i32_bytes)
}

fn (mut p WireProtocol) pack_array_u8(au []u8) {
	array_u8_bytes := marshal_array_u8(au)
	p.buf = arrays.append(p.buf, array_u8_bytes)
}

fn (mut p WireProtocol) pack_string(s string) {
	array_u8_string := marshal_string(s)
	p.buf = arrays.append(p.buf, array_u8_string)
}

fn (mut p WireProtocol) append_array_u8(au []u8) {
	p.buf = arrays.append(p.buf, au)
}

fn get_system_user() []u8 {
	system_user := os.getenv('USER')
	if system_user == '' {
		return os.getenv('USERNAME').bytes()
	}
	return system_user.bytes()
}

fn get_hostname() []u8 {
	hostname := os.hostname() or { '' }
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
	p.conn.flush()!
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
	mut buf := []u8{len: n}
	mut read := 0
	mut total_read := 0
	for total_read < n {
		read = p.conn.read(mut buf[total_read..n])!
		total_read += read
	}
	return buf
}

fn received_packets_padding(n int) int {
	remainder := n % 4
	if remainder > 0 {
		return 4 - remainder
	}
	return 0
}

fn (mut p WireProtocol) receive_packets_alignment(n i32) ![]u8 {
	padding := received_packets_padding(n)
	buf := p.receive_packets(n + padding)!
	res := buf[0..n] // exclude padding
	return res
}

// TODO refactor, function is too big
fn (mut p WireProtocol) parse_status_vector() !([]int, int, string) {
	mut sql_code := 0
	mut gds_code := 0
	mut gds_codes := []int{}
	mut num_arg := 0
	mut message := ''

	mut b := p.receive_packets(4)!
	mut n := i32(binary.big_endian_u32(b))
	for n != isc_arg_end {
		match n {
			isc_arg_gds {
				b = p.receive_packets(4)!
				gds_code = i32(binary.big_endian_u32(b))
				if gds_code != 0 {
					gds_codes = arrays.concat(gds_codes, gds_code)
					msg := get_error_message(gds_code) or { err.msg() }
					message += msg
					num_arg = 0
				}
			}
			isc_arg_number {
				b = p.receive_packets(4)!
				num := i32(binary.big_endian_u32(b))
				if gds_code == 335544436 {
					sql_code = num
				}
				num_arg++
				message = message.replace_once('@${num_arg}', '${num}')
			}
			isc_arg_string {
				b = p.receive_packets(4)!
				nbytes := i32(binary.big_endian_u32(b))
				b = p.receive_packets_alignment(nbytes)!
				s := b.bytestr()
				num_arg++
				message = message.replace_once('@${num_arg}', s)
			}
			isc_arg_interpreted {
				b = p.receive_packets(4)!
				nbytes := i32(binary.big_endian_u32(b))
				b = p.receive_packets_alignment(nbytes)!
				s := b.bytestr()
				message += s
			}
			isc_arg_sql_state {
				b = p.receive_packets(4)!
				nbytes := i32(binary.big_endian_u32(b))
				b = p.receive_packets_alignment(nbytes)!
				_ := b.bytestr() // skip status code
			}
			else {}
		}
		b = p.receive_packets(4)!
		n = i32(binary.big_endian_u32(b))
	}

	return gds_codes, sql_code, message
}

fn (mut p WireProtocol) parse_generic_response() !(i32, []u8, []u8) {
	b := p.receive_packets(16)!
	object_handle := i32(binary.big_endian_u32(b[..4]))
	object_id := b[4..12]
	response_buffer_length := i32(binary.big_endian_u32(b[12..]))
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

// TODO refactor, this function is too big.
fn (mut p WireProtocol) parse_connect_response(user string, password string, options map[string]string, client_public big.Integer, client_secret big.Integer) ! {
	mut b := p.receive_packets(4)!
	mut opcode := big_endian_i32(b)

	for opcode == op_dummy {
		b = p.receive_packets(4) or { []u8{} }
		opcode = big_endian_i32(b)
	}

	if opcode == op_reject {
		return error(format_error_message('Connection rejected'))
	}

	if opcode == op_response {
		p.parse_generic_response()!
	}

	b = p.receive_packets(12) or { []u8{} }
	p.protocol_version = i32(b[3])
	p.accept_architecture = big_endian_i32(b[4..8])
	p.accept_type = big_endian_i32(b[8..12])

	if opcode == op_cond_accept || opcode == op_accept_data {
		b = p.receive_packets(4) or { []u8{} }
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
				// TODO normalize user

				if data.len == 0 {
					p.continue_authentication(pad(client_public), p.plugin_name, plugin_list,
						'')!
					b = p.receive_packets(4) or { []u8{} }
					println(b)
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
				println(data[..2]) // [64, 0] = 16384 ( too big) TODO BLOCKING
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
			return error(format_error_message('Protocol error'))
		}
	}

	return
}

fn get_wire_crypt_from_options(o map[string]string) bool {
	if 'wire_crypt' in o {
		return parse_bool(o['wire_crypt'])
	}
	return true
}

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-attach-identification
fn (mut p WireProtocol) connect(db_name string, user string, options map[string]string, client_public_key big.Integer) ! {
	// logger.debug('connect')
	wire_crypt := get_wire_crypt_from_options(options)
	uid := user_identification(user, options['auth_plugin_name'], wire_crypt, client_public_key)
	p.pack_i32(op_connect)
	p.pack_i32(op_attach)
	p.pack_i32(connect_version_3)
	p.pack_i32(arch_type_generic)
	p.pack_string(db_name) // Database path or alias
	p.pack_i32(supported_protocols_count) // Count of protocol versions understood
	p.pack_array_u8(uid)
	p.append_array_u8(supported_protocols_bytes)
	p.send_packets()!
}

fn (mut p WireProtocol) attach(database string, user string, password string, role string) ! {
	// logger.debug('attach')
	charset_bytes := p.charset.bytes()
	user_bytes := user.bytes()
	password_bytes := password.bytes()
	role_bytes := role.bytes()

	executable := get_executable()
	executable_bytes := executable.bytes()

	pid := i32(os.getpid())

	// https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-attach-attachment
	// https://github.com/FirebirdSQL/jaybird/blob/master/src/main/org/firebirdsql/gds/impl/ParameterBufferBase.java
	dpb_version := [u8(isc_dpb_version1)]
	dpb_sql_dialect := arrays.append([u8(isc_dpb_sql_dialect), u8(4)], marshal_i32(3))
	dpb_lc_type := arrays.append([u8(isc_dpb_lc_ctype), u8(charset_bytes.len)], charset_bytes)
	dpb_role_name := arrays.append([u8(isc_dpb_sql_role_name), u8(role_bytes.len)], role_bytes)
	dpb_user_name := arrays.append([u8(isc_dpb_user_name), u8(user_bytes.len)], user_bytes)
	dpb_password := arrays.append([u8(isc_dpb_password), u8(password_bytes.len)], password_bytes)
	dpb_process_id := arrays.append([u8(isc_dpb_process_id), u8(4)], marshal_i32(pid))
	dpb_process_name := arrays.append([u8(isc_dpb_process_name), u8(executable.len)],
		executable_bytes)
	dpb_utf8_filename := [u8(isc_dpb_utf8_filename), u8(1), u8(1)]
	mut dpb := append(dpb_version, dpb_sql_dialect, dpb_lc_type, dpb_role_name, dpb_user_name,
		dpb_password, dpb_process_id, dpb_process_name, dpb_utf8_filename)

	if p.auth_data.len > 0 {
		specific_auth_data_hex := hex.encode(p.auth_data)
		specific_auth_data_bytes := specific_auth_data_hex.bytes()
		dpb_specific_auth_data := arrays.append([u8(isc_dpb_specific_auth_data),
			u8(specific_auth_data_bytes.len)], specific_auth_data_bytes)
		dpb = arrays.append(dpb, dpb_specific_auth_data)
	}

	if p.timezone != '' {
		timezone_bytes := p.timezone.bytes()
		dpb_session_time_zone := arrays.append([u8(isc_dpb_session_time_zone), u8(timezone_bytes.len)],
			timezone_bytes)
		dpb = arrays.append(dpb, dpb_session_time_zone)
	}

	p.pack_i32(op_attach)
	p.pack_i32(0) // Database Object ID
	p.pack_string(database)
	p.append_array_u8(dpb)
	p.send_packets()!
}

fn (mut p WireProtocol) detach() ! {
	return error('TODO')
}

fn (mut p WireProtocol) transaction(tpb []u8) ! {
	return error('TODO')
}

fn (mut p WireProtocol) commit(handle i32) ! {
	return error('TODO')
}

fn (mut p WireProtocol) rollback(handle i32) ! {
	return error('TODO')
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
