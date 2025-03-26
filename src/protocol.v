module firebird

import arrays
import math.big
import net
import os
import time

const plugin_list = 'Srp256,Srp'
const buffer_length = 1024
const legacy_auth_error = 'LegacyAuth is not supported: ${low_priority_todo}'
const info_sql_select_describe_vars = [u8(isc_info_sql_select), isc_info_sql_describe_vars,
	isc_info_sql_sqlda_seq, isc_info_sql_type, isc_info_sql_sub_type, isc_info_sql_scale,
	isc_info_sql_length, isc_info_sql_null_ind, isc_info_sql_field, isc_info_sql_relation,
	isc_info_sql_owner, isc_info_sql_alias, isc_info_sql_describe_end]

// Protocol Types (accept_type)
const ptype_batch_send = 3 // Batch sends, no asynchrony
const ptype_out_of_band = 4 // Batch sends w/ out of band notification
const ptype_lazy_send = 5 // Deferred packets delivery

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

fn new_wire_protocol(addr string, timezone string) !WireProtocol {
	conn := net.dial_tcp(addr)!
	return WireProtocol{
		buf:              []u8{} // TODO performance enhancement: make it { len: buffer_length }
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
	p.buf = arrays.append(p.buf, marshal_i32_big_endian(i))
}

fn (mut p WireProtocol) pack_bytes(au []u8) {
	p.buf = arrays.append(p.buf, marshal_bytes(au))
}

fn (mut p WireProtocol) pack_string(s string) {
	p.buf = arrays.append(p.buf, marshal_string(s))
}

fn (mut p WireProtocol) append_bytes(au []u8) {
	p.buf = arrays.append(p.buf, au)
}

fn (mut p WireProtocol) clear_buffer() {
	p.buf = []u8{}
}

fn (mut p WireProtocol) send_packets() !int {
	mut written := 0
	mut n := 0
	for written < p.buf.len {
		n = p.conn.write(p.buf[written..]) or {
			p.conn.flush()!
			p.clear_buffer()
			return err
		}
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

fn (mut p WireProtocol) receive_aligned_packets(n i32) ![]u8 {
	if n == 0 {
		return []u8{}
	}

	padding := received_packets_padding(n)
	buf := p.receive_packets(n + padding)!
	res := buf[..n] // exclude padding
	return res
}

fn (mut p WireProtocol) parse_status_vector() !([]int, int, string) {
	mut sql_code := 0
	mut gds_code := 0
	mut gds_codes := []int{}
	mut num_arg := 0
	mut message := ''

	mut b := p.receive_packets(4)!
	mut n := parse_i32(b)
	for n != isc_arg_end {
		match n {
			isc_arg_gds {
				b = p.receive_packets(4)!
				gds_code = parse_i32(b)
				if gds_code != 0 {
					gds_codes = arrays.concat(gds_codes, gds_code)
					msg := get_error_message(gds_code) or { err.msg() }
					message += msg
					num_arg = 0
				}
			}
			isc_arg_number {
				b = p.receive_packets(4)!
				num := parse_i32(b)
				if gds_code == 335544436 {
					sql_code = num
				}
				num_arg++
				message = message.replace_once('@${num_arg}', '${num}')
			}
			isc_arg_string {
				b = p.receive_packets(4)!
				nbytes := parse_i32(b)
				b = p.receive_aligned_packets(nbytes)!
				s := b.bytestr()
				num_arg++
				message = message.replace_once('@${num_arg}', s)
			}
			isc_arg_interpreted {
				b = p.receive_packets(4)!
				nbytes := parse_i32(b)
				b = p.receive_aligned_packets(nbytes)!
				s := b.bytestr()
				message += s
			}
			isc_arg_sql_state {
				b = p.receive_packets(4)!
				nbytes := parse_i32(b)
				b = p.receive_aligned_packets(nbytes)!
				_ := b.bytestr() // skip status code
			}
			else {}
		}
		b = p.receive_packets(4)!
		n = parse_i32(b)
	}

	return gds_codes, sql_code, message
}

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-responses-generic
fn (mut p WireProtocol) parse_generic_response() !(i32, []u8, []u8) {
	b := p.receive_packets(16)!
	object_handle := parse_i32(b[..4])
	object_id := b[4..12]
	response_buffer_length := parse_i32(b[12..])
	response_buffer := p.receive_aligned_packets(response_buffer_length)!

	gds_code_list, sql_code, message := p.parse_status_vector()!
	if gds_code_list.len > 0 || sql_code != 0 {
		return error(format_error_message(message))
	}
	return object_handle, object_id, response_buffer
}

// https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-responses-generic
fn (mut p WireProtocol) generic_response() !(i32, []u8, []u8) {
	mut b := p.receive_packets(4)!
	for parse_i32(b) == op_dummy {
		b = p.receive_packets(4)!
	}

	for parse_i32(b) == op_crypt_key_callback {
		p.crypt_callback()!
		p.receive_packets(12)!
		b = p.receive_packets(4)!
	}

	for parse_i32(b) == op_response && p.lazy_response_count > 0 {
		p.lazy_response_count--
		p.parse_generic_response()!
		b = p.receive_packets(4)!
	}

	op_error_code := parse_i32(b)
	if op_error_code != op_response {
		return error(format_op_error(op_error_code))
	}
	return p.parse_generic_response()!
}

fn (mut p WireProtocol) get_encrypt_plugin_and_nonce(opcode i32, auth_data []u8, options map[string]string) !(string, []u8) {
	if opcode != op_cond_accept {
		return '', []u8{}
	}

	p.continue_authentication(auth_data, options['auth_plugin_name'], '')!
	_, _, buf := p.generic_response()!
	return choose_wire_crypt(buf)!
}

// TODO refactor, this function is too big.
fn (mut p WireProtocol) parse_connect_response(user string, password string, options map[string]string, client_public_key big.Integer, client_secret_key big.Integer) ! {
	mut b := p.receive_packets(4)!
	mut opcode := parse_i32(b)

	for opcode == op_dummy {
		b = p.receive_packets(4) or { []u8{} }
		opcode = parse_i32(b)
	}

	if opcode == op_reject {
		return error(format_error_message('Connection rejected'))
	}

	if opcode == op_response {
		p.parse_generic_response()!
	}

	b = p.receive_packets(12)! // if error next line causes out of bound memory access
	p.protocol_version = i32(b[3]) // b[..3] are the taken by fb_protocol_flag
	p.accept_architecture = parse_i32(b[4..8])
	p.accept_type = parse_i32(b[8..12])
	p.user = user
	p.password = password

	if opcode == op_cond_accept || opcode == op_accept_data {
		b = p.receive_packets(4) or { []u8{} }
		mut ln := parse_i32(b)
		mut data := p.receive_aligned_packets(ln) or { []u8{} }

		b = p.receive_packets(4) or { []u8{} }
		ln = parse_i32(b)
		plugin_name := p.receive_aligned_packets(ln) or { []u8{} }
		p.plugin_name = plugin_name.bytestr()

		b = p.receive_packets(4) or { []u8{} }
		is_authenticated := parse_i32(b)

		b = p.receive_packets(4) or { []u8{} }
		ln = parse_i32(b)
		p.receive_aligned_packets(ln)! // keys

		mut auth_data := []u8{}
		mut session_key := []u8{}
		if is_authenticated == 0 {
			if p.plugin_name == 'Srp' || p.plugin_name == 'Srp256' {
				// TODO normalize user

				if data.len == 0 {
					p.continue_authentication(big_integer_to_bytes(client_public_key),
						p.plugin_name, '')!
					b = p.receive_packets(4) or { []u8{} }
					op := parse_i32(b)
					if op == op_response {
						p.parse_generic_response()! // error occurred
					}

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_i32(b)
					data = p.receive_aligned_packets(ln) or { []u8{} }

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_i32(b)
					p.receive_aligned_packets(ln) or { []u8{} } // plugin_name

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_i32(b)
					p.receive_aligned_packets(ln) or { []u8{} } // plugin_list

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_i32(b)
					p.receive_aligned_packets(ln) or { []u8{} } // keys
				}

				ln = parse_i16(data[..2]) // server salt length
				server_public_key := big.integer_from_radix(data[ln + 4..].bytestr(),
					16)!
				auth_data, session_key = get_client_proof(user.to_upper(), password, data[2..ln + 2],
					client_public_key, server_public_key, client_secret_key, p.plugin_name)
			} else if p.plugin_name == 'Legacy_Auth' {
				return error(format_error_message(legacy_auth_error))
			} else {
				return error(format_error_message('Unauthorized'))
			}
		}

		// encrypt
		plugin, nonce := p.get_encrypt_plugin_and_nonce(opcode, auth_data, options)!
		wire_crypt := get_wire_crypt_from_options(options)
		if plugin != '' && wire_crypt && session_key.len != 0 {
			p.crypt(plugin)!
			p.conn.set_crypt_key(plugin, session_key, nonce)!
			_, _, _ := p.generic_response()!
		} else {
			p.auth_data = auth_data // use later opAttach and opCreate
		}
	} else {
		if opcode != op_accept {
			return error(format_error_message('Protocol error'))
		}
	}
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
	p.pack_bytes(uid)
	p.append_bytes(supported_protocols_bytes)
	p.send_packets()!
}

fn (mut p WireProtocol) attach(database string, user string, password string, role string) ! {
	charset_bytes := p.charset.bytes()
	user_bytes := user.to_upper().bytes()
	password_bytes := password.bytes()
	role_bytes := role.bytes()
	executable_bytes := get_executable().bytes()
	pid := i32(os.getpid())

	// https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-attach-attachment
	// https://github.com/FirebirdSQL/jaybird/blob/48d132b00a160073e60c5babad853d509563cb69/src/main/org/firebirdsql/gds/impl/ParameterBufferBase.java
	dpb_version := [u8(isc_dpb_version1)]
	dpb_sql_dialect := arrays.append([u8(isc_dpb_sql_dialect), 4], marshal_i32_small_endian(3))
	dpb_lc_type := arrays.append([u8(isc_dpb_lc_ctype), u8(charset_bytes.len)], charset_bytes)
	dpb_user_name := arrays.append([u8(isc_dpb_user_name), u8(user_bytes.len)], user_bytes)
	dpb_password := arrays.append([u8(isc_dpb_password), u8(password_bytes.len)], password_bytes)
	dpb_role_name := arrays.append([u8(isc_dpb_sql_role_name), u8(role_bytes.len)], role_bytes)
	dpb_process_id := arrays.append([u8(isc_dpb_process_id), 4], marshal_i32_small_endian(pid))
	dpb_process_name := arrays.append([u8(isc_dpb_process_name), u8(executable_bytes.len)],
		executable_bytes)
	dpb_utf8_filename := [u8(isc_dpb_utf8_filename), 1, 1]

	dpb := attach_append_timezone(attach_append_auth_data(append(dpb_version, dpb_sql_dialect,
		dpb_lc_type, dpb_user_name, dpb_password, dpb_role_name, dpb_process_id, dpb_process_name,
		dpb_utf8_filename), p.auth_data), p.timezone)

	p.pack_i32(op_attach)
	p.pack_i32(0) // Database Object ID
	p.pack_string(database)
	p.pack_bytes(dpb)
	p.send_packets()!
}

fn (mut p WireProtocol) detach() ! {
	p.pack_i32(op_detach)
	p.pack_i32(p.db_handle)
	p.send_packets()!
}

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/remote/protocol.cpp#L794
fn (mut p WireProtocol) continue_authentication(auth_data []u8, auth_plugin_name string, keys string) ! {
	p.pack_i32(op_cont_auth)
	p.pack_string(auth_data.hex())
	p.pack_string(auth_plugin_name)
	p.pack_string(plugin_list)
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
	p.pack_i32(op_crypt_key_callback)
	p.pack_i32(0)
	p.pack_i32(buffer_length)
	p.send_packets()!
}

fn (mut p WireProtocol) param_to_blr(param Value) []u8 {
	match param {
		string {}
		i32 {}
		i64 {}
		f64 {}
		time.Time {}
		bool {}
		[]u8 {}
		else {}
	}
	return []u8{}
}

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-statements-execute
// https://github.com/FirebirdSQL/jaybird/blob/48d132b00a160073e60c5babad853d509563cb69/src/main/org/firebirdsql/gds/ng/wire/DefaultBlrCalculator.java
fn (mut p WireProtocol) params_to_blr(tx_handle i32, params []Value, protocol_version i32) ([]u8, []u8) {
	param_count := params.len * 2
	mut blr := [u8(blr_version5), blr_begin, blr_message, 0, u8(param_count & mask_byte),
		u8(param_count >> 8)]

	// TODO link source
	// TODO split to independent function
	mut values := []u8{}
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
		values = arrays.append(values, [u8(mod_res.int())])
		null_indicator = null_indicator / big256
	}

	for i := 0; i < params.len; i++ {
		blr = arrays.append(blr, p.param_to_blr(params[i]))
		blr = arrays.append(blr, [u8(blr_short), 0])
	}
	blr = arrays.append(blr, [u8(blr_end), blr_eoc])
	return blr, values
}

fn (mut p WireProtocol) transaction(tpb []u8) ! {
	p.pack_i32(op_transaction)
	p.pack_i32(p.db_handle)
	p.pack_bytes(tpb)
	p.send_packets()!
}

fn (mut p WireProtocol) commit(tx_handle i32) ! {
	p.pack_i32(op_commit)
	p.pack_i32(tx_handle)
	p.send_packets()!
}

fn (mut p WireProtocol) rollback(tx_handle i32) ! {
	p.pack_i32(op_rollback)
	p.pack_i32(tx_handle)
	p.send_packets()!
}

fn (mut p WireProtocol) allocate_statement() ! {
	p.pack_i32(op_allocate_statement)
	p.pack_i32(p.db_handle)
	p.send_packets()!
}

fn (mut p WireProtocol) prepare_statement(stmt_handle i32, tx_handle i32, query string) ! {
	p.pack_i32(op_prepare_statement)
	p.pack_i32(tx_handle)
	p.pack_i32(stmt_handle)
	p.pack_i32(3) // dialect 3
	p.pack_string(query)
	p.pack_bytes(arrays.append([u8(isc_info_sql_stmt_type)], info_sql_select_describe_vars))
	p.pack_i32(buffer_length)
	p.send_packets()!
}

// https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-statements-execute
// op_execute is used for DDL and DML statements
fn (mut p WireProtocol) execute(stmt_handle i32, tx_handle i32, params []Value) ! {
	p.pack_i32(op_execute)
	p.pack_i32(stmt_handle)
	p.pack_i32(tx_handle)
	if params.len == 0 {
		p.pack_bytes([]u8{len: 0})
		p.pack_i32(0)
		p.pack_i32(0)
	} else {
		blr, values := p.params_to_blr(tx_handle, params, p.protocol_version)
		p.pack_bytes(blr)
		p.pack_i32(0)
		p.pack_i32(1)
		p.append_bytes(values)
	}
	p.append_bytes(marshal_i32_big_endian(0))
	p.send_packets()!
}
