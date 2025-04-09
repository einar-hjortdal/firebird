module firebird

import arrays
import encoding.hex
import math.big
import net
import os
import strings
import time

const plugin_list = 'Srp256,Srp'
const buffer_length = 1024
const legacy_auth_error = 'LegacyAuth is not supported: ${low_priority_todo}'
const info_sql_select_describe_vars = [
	u8(isc_info_sql_select),
	isc_info_sql_describe_vars,
	isc_info_sql_sqlda_seq,
	isc_info_sql_type,
	isc_info_sql_sub_type,
	isc_info_sql_scale,
	isc_info_sql_length,
	isc_info_sql_null_ind,
	isc_info_sql_field,
	isc_info_sql_relation,
	isc_info_sql_owner,
	isc_info_sql_alias,
	isc_info_sql_describe_end,
]

// Protocol Types (accept_type)
const ptype_batch_send = 3 // Batch sends, no asynchrony
const ptype_out_of_band = 4 // Batch sends w/ out of band notification
const ptype_lazy_send = 5 // Deferred packets delivery

struct WireProtocol {
mut:
	buf []u8

	conn      &WireChannel
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

	timezone string
	charset  string
	// charset_byte_len int
}

fn new_wire_protocol(addr string, timezone string) !&WireProtocol {
	conn := net.dial_tcp(addr)!
	return &WireProtocol{
		buf:      []u8{} // TODO performance enhancement: make it { len: buffer_length }
		conn:     new_wire_channel(conn)
		addr:     addr
		timezone: timezone
		charset:  charset_utf8
		// charset_byte_len: 4
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
	mut n := parse_big_endian_i32(b)
	for n != isc_arg_end {
		match n {
			isc_arg_gds {
				b = p.receive_packets(4)!
				gds_code = parse_big_endian_i32(b)
				if gds_code != 0 {
					gds_codes = arrays.concat(gds_codes, gds_code)
					msg := get_error_message(gds_code) or { err.msg() }
					message += msg
					num_arg = 0
				}
			}
			isc_arg_number {
				b = p.receive_packets(4)!
				num := parse_big_endian_i32(b)
				if gds_code == 335544436 {
					sql_code = num
				}
				num_arg++
				message = message.replace_once('@${num_arg}', '${num}')
			}
			isc_arg_string {
				b = p.receive_packets(4)!
				nbytes := parse_big_endian_i32(b)
				b = p.receive_aligned_packets(nbytes)!
				s := b.bytestr()
				num_arg++
				message = message.replace_once('@${num_arg}', s)
			}
			isc_arg_interpreted {
				b = p.receive_packets(4)!
				nbytes := parse_big_endian_i32(b)
				b = p.receive_aligned_packets(nbytes)!
				s := b.bytestr()
				message += s
			}
			isc_arg_sql_state {
				b = p.receive_packets(4)!
				nbytes := parse_big_endian_i32(b)
				b = p.receive_aligned_packets(nbytes)!
				_ := b.bytestr() // skip status code
			}
			else {}
		}
		b = p.receive_packets(4)!
		n = parse_big_endian_i32(b)
	}

	return gds_codes, sql_code, message
}

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-responses-generic
fn (mut p WireProtocol) parse_generic_response() !(i32, []u8, []u8) {
	b := p.receive_packets(16)!
	object_handle := parse_big_endian_i32(b[..4])
	object_id := b[4..12]
	response_buffer_length := parse_big_endian_i32(b[12..])
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

	// TODO this is repeated in parse_fetch_response, extract as utility function
	for parse_big_endian_i32(b) == op_dummy {
		b = p.receive_packets(4)!
	}

	for parse_big_endian_i32(b) == op_crypt_key_callback {
		p.crypt_callback()!
		p.receive_packets(12)!
		b = p.receive_packets(4)!
	}

	// TODO this is repeated in parse_fetch_response, extract as utility function
	for parse_big_endian_i32(b) == op_response && p.lazy_response_count > 0 {
		p.lazy_response_count--
		p.parse_generic_response()!
		b = p.receive_packets(4)!
	}

	op_error_code := parse_big_endian_i32(b)
	if op_error_code != op_response {
		return error(format_error_message('op_response ${op_error_code}'))
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
	mut opcode := parse_big_endian_i32(b)

	for opcode == op_dummy {
		b = p.receive_packets(4) or { []u8{} }
		opcode = parse_big_endian_i32(b)
	}

	if opcode == op_reject {
		return error(format_error_message('Connection rejected'))
	}

	if opcode == op_response {
		p.parse_generic_response()!
	}

	b = p.receive_packets(12)! // if error next line causes out of bound memory access
	p.protocol_version = i32(b[3]) // b[..3] are the taken by fb_protocol_flag
	p.accept_architecture = parse_big_endian_i32(b[4..8])
	p.accept_type = parse_big_endian_i32(b[8..12])
	p.user = user
	p.password = password

	if opcode == op_cond_accept || opcode == op_accept_data {
		b = p.receive_packets(4) or { []u8{} }
		mut ln := parse_big_endian_i32(b)
		mut data := p.receive_aligned_packets(ln) or { []u8{} }

		b = p.receive_packets(4) or { []u8{} }
		ln = parse_big_endian_i32(b)
		plugin_name := p.receive_aligned_packets(ln) or { []u8{} }
		p.plugin_name = plugin_name.bytestr()

		b = p.receive_packets(4) or { []u8{} }
		is_authenticated := parse_big_endian_i32(b)

		b = p.receive_packets(4) or { []u8{} }
		ln = parse_big_endian_i32(b)
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
					op := parse_big_endian_i32(b)
					if op == op_response {
						p.parse_generic_response()! // error occurred
					}

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_big_endian_i32(b)
					data = p.receive_aligned_packets(ln) or { []u8{} }

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_big_endian_i32(b)
					p.receive_aligned_packets(ln) or { []u8{} } // plugin_name

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_big_endian_i32(b)
					p.receive_aligned_packets(ln) or { []u8{} } // plugin_list

					b = p.receive_packets(4) or { []u8{} }
					ln = parse_big_endian_i32(b)
					p.receive_aligned_packets(ln) or { []u8{} } // keys
				}

				ln = parse_little_endian_i16(data[..2]) // server salt length
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
	// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/src/main/org/firebirdsql/gds/impl/ParameterBufferBase.java
	mut dpb := strings.new_builder(31)
	dpb.write_u8(isc_dpb_version1)
	dpb.write_u8(isc_dpb_sql_dialect)
	dpb.write_u8(4)
	dpb.write(marshal_i32_small_endian(3)) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_lc_ctype)
	dpb.write_u8(u8(charset_bytes.len))
	dpb.write(charset_bytes) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_user_name)
	dpb.write_u8(u8(user_bytes.len))
	dpb.write(user_bytes) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_user_name)
	dpb.write_u8(u8(user_bytes.len))
	dpb.write(user_bytes) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_password)
	dpb.write_u8(u8(password_bytes.len))
	dpb.write(password_bytes) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_sql_role_name)
	dpb.write_u8(u8(role_bytes.len))
	dpb.write(role_bytes) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_process_id)
	dpb.write_u8(4)
	dpb.write(marshal_i32_small_endian(pid)) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_process_name)
	dpb.write_u8(u8(executable_bytes.len))
	dpb.write(executable_bytes) or { panic(err) } // does not return any error

	dpb.write_u8(isc_dpb_utf8_filename)
	dpb.write_u8(1)
	dpb.write_u8(1)

	if p.timezone != '' {
		timezone_bytes := p.timezone.bytes()

		dpb.write_u8(isc_dpb_session_time_zone)
		dpb.write_u8(u8(timezone_bytes.len))
		dpb.write(timezone_bytes) or { panic(err) } // does not return any error
	}

	if p.auth_data.len != 0 {
		specific_auth_data_bytes := hex.encode(p.auth_data).bytes()

		dpb.write_u8(isc_dpb_specific_auth_data)
		dpb.write_u8(u8(specific_auth_data_bytes.len))
		dpb.write(specific_auth_data_bytes) or { panic(err) } // does not return any error
	}

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

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-disconnect
fn (mut p WireProtocol) disconnect() ! {
	p.pack_i32(op_disconnect)
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

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-statements-execute
// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/src/main/org/firebirdsql/gds/ng/wire/DefaultBlrCalculator.java
fn (mut p WireProtocol) params_to_blr(tx_handle i32, params []Value, protocol_version i32) ([]u8, []u8) {
	mut b := initialize_blr_data(params) // Parameters in BLR format
	mut v := initialize_values_data(params) // Parameter values

	for i := 0; i < params.len; i++ {
		param := params[i]
		match param {
			string {
				if param.len < max_char_length {
					blr, value := bytes_to_blr(param.bytes())
					_ := b.write(blr) or { 0 } // does not return any error
					_ := v.write(value) or { 0 } // does not return any error
				} else {
					// TODO
					// p.create_blob(param, tx_handle)
					// b.write_u8(9)
					// b.write_u8(0)
				}
			}
			[]u8 {
				if param.len < max_char_length {
					blr, value := bytes_to_blr(*param) // https://github.com/vlang/v/issues/24054#issuecomment-2758173475
					_ := b.write(blr) or { 0 } // does not return any error
					_ := v.write(value) or { 0 } // does not return any error
				} else {
					// TODO
					// p.create_blob(param, tx_handle)
					// b.write_u8(9)
					// b.write_u8(0)
				}
			}
			i32 {
				blr, value := i32_to_blr(param)
				_ := b.write(blr) or { 0 } // does not return any error
				_ := v.write(value) or { 0 } // does not return any error
			}
			i64 {
				// TODO
			}
			f64 {
				blr, value := f64_to_blr(param)
				_ := b.write(blr) or { 0 } // does not return any error
				_ := v.write(value) or { 0 } // does not return any error
			}
			time.Time {
				// TODO
			}
			bool {
				if param {
					_ := v.write(marshal_i32_big_endian(1)) or { 0 } // does not return any error
				} else {
					_ := v.write(marshal_i32_big_endian(0)) or { 0 } // does not return any error
				}
			}
			Null {
				b.write_byte(blr_text)
				b.write_byte(0)
				b.write_byte(0)
			}
			else {
				// TODO
			}
		}
		b.write_u8(blr_short)
		b.write_u8(0)
	}
	b.write_u8(blr_end)
	b.write_u8(blr_eoc)
	return b, v
}

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-statements-information
fn (mut p WireProtocol) information_request(stmt_handle i32, vars []u8) ! {
	p.pack_i32(op_info_sql)
	p.pack_i32(stmt_handle)
	p.pack_i32(0)
	p.pack_bytes(vars)
	p.pack_i32(buffer_length)
	p.send_packets()!
}

// TODO refactor
// - remove mut sqlda declaration
// - remove for loop nesting
// Note: it seems like buf always starts with 21 (isc_info_sql_stmt_type)
fn (mut p WireProtocol) parse_xsqlda(buf []u8, stmt_handle i32) !(i32, XSQLDA) {
	stmt_type, end_parameter_description_index := parse_statement_type(buf)!
	mut xsqlda := XSQLDA{}
	for i := end_parameter_description_index; i < buf.len; {
		if buf[i] == u8(isc_info_sql_select) && buf[i + 1] == u8(isc_info_sql_describe_vars) {
			i += 2
			len := parse_little_endian_i16(buf[i..i + 2])
			i += 2
			col_len := parse_little_endian_i32(buf[i..i + len])
			xsqlda = new_xsqlda(col_len)
			mut next_index := xsqlda.parse_select_items(buf[i + len..])!
			for next_index > 0 {
				mut vars := strings.new_builder(2 + info_sql_select_describe_vars.len)
				vars.write_u8(isc_info_sql_sqlda_start)
				vars.write_u8(2)
				vars.write(info_sql_select_describe_vars) or { panic(err) } // does not return any error
				p.information_request(stmt_handle, vars)!
				_, _, var_data := p.generic_response()!
				var_len := parse_little_endian_i16(var_data[2..4])
				next_index = xsqlda.parse_select_items(var_data[4 + var_len..])!
			}
		} else {
			break
		}
	}
	return stmt_type, xsqlda
}

// TODO refactor
fn (mut p WireProtocol) sql_response(xsqlda XSQLDA) ![]Value {
	mut b := p.receive_packets(4)!
	for parse_big_endian_i32(b) == op_dummy {
		b = p.receive_packets(4)!
	}

	response := parse_big_endian_i32(b)
	if response != op_sql_response {
		return error(format_error_message('received ${response}, not op_sql_response'))
	}

	b = p.receive_packets(4)!
	count := parse_big_endian_i32(b)
	if count == 0 {
		return []Value{}
	}

	mut res := []Value{len: xsqlda.vars.len, init: Value(Null{})}

	// TODO this part is repeated in parse_fetch_response. Abstract to utility function
	big256 := big.integer_from_i64(256)
	mut n := xsqlda.vars.len / 8
	if xsqlda.vars.len % 8 == 0 {
		n++
	}

	mut null_indicator := big.integer_from_i64(0)
	b = p.receive_aligned_packets(i32(n))!
	for n = b.len; n > 0; n-- {
		null_indicator = null_indicator * big256 + big.integer_from_i64(b[n - 1])
	}

	for i := 0; i < xsqlda.vars.len; i++ {
		if null_indicator.get_bit(u32(i)) {
			continue
		}
		x := xsqlda.vars[i]
		mut len := i32(0)
		if x.io_length() < 0 {
			b = p.receive_packets(4)!
			len = parse_big_endian_i32(b)
		} else {
			len = i32(x.io_length())
		}
		raw_value := p.receive_aligned_packets(len)!
		res[i] = x.get_value(raw_value, p.timezone, p.charset)!
	}

	return res
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
		p.pack_i32(0)
		p.pack_i32(0)
		p.pack_i32(0)
	} else {
		b, v := p.params_to_blr(tx_handle, params, p.protocol_version)
		p.pack_bytes(b)
		p.pack_i32(0)
		p.pack_i32(1)
		p.append_bytes(v)
	}
	p.append_bytes(marshal_i32_big_endian(0)) // timeout https://github.com/FirebirdSQL/firebird/blob/08cb3f94e96fc80ed4ec786d31def367e8e58d7c/src/remote/protocol.cpp#L668
	// TODO proper fetch_scroll value?
	p.append_bytes(marshal_i32_big_endian(0)) // fetch_scroll https://github.com/FirebirdSQL/firebird/blob/08cb3f94e96fc80ed4ec786d31def367e8e58d7c/src/remote/protocol.cpp#L670
	p.send_packets()!
}

// op_execute2 is used for stored procedures
// TODO merge executes to reduce repetitions?
fn (mut p WireProtocol) execute_stored_procedure(stmt_handle i32, tx_handle i32, params []Value, output_blr_params []u8) ! {
	p.pack_i32(op_execute2)
	p.pack_i32(stmt_handle)
	p.pack_i32(tx_handle)
	if params.len == 0 {
		p.pack_i32(0)
		p.pack_i32(0)
		p.pack_i32(0)
	} else {
		b, v := p.params_to_blr(tx_handle, params, p.protocol_version)
		p.pack_bytes(b)
		p.pack_i32(0)
		p.pack_i32(1)
		p.append_bytes(v)
	}
	p.append_bytes(output_blr_params)
	p.pack_i32(0)
	p.append_bytes(marshal_i32_big_endian(0)) // timeout https://github.com/FirebirdSQL/firebird/blob/08cb3f94e96fc80ed4ec786d31def367e8e58d7c/src/remote/protocol.cpp#L668
	// TODO value from https://github.com/FirebirdSQL/jaybird/blob/c152a12d8dec10a3f7bf4013b4b39ad5dfed85b6/src/main/org/firebirdsql/gds/ng/wire/version18/V18Statement.java#L107
	p.append_bytes(marshal_i32_big_endian(0)) // fetch_scroll https://github.com/FirebirdSQL/firebird/blob/08cb3f94e96fc80ed4ec786d31def367e8e58d7c/src/remote/protocol.cpp#L670
	p.send_packets()!
}

fn (mut p WireProtocol) cancel(kind i32) ! {
	p.pack_i32(op_cancel)
	p.pack_i32(kind)
	p.send_packets()!
}

fn (mut p WireProtocol) fetch(stmt_handle i32, blr []u8) ! {
	p.pack_i32(op_fetch)
	p.pack_i32(stmt_handle)
	p.pack_bytes(blr)
	p.pack_i32(0)
	p.pack_i32(default_fetch_rows)
	p.send_packets()!
}

// TODO protocol 18 op_fetch_scroll?

// TODO fetch all rows, not just some (return no bool)
fn (mut p WireProtocol) parse_fetch_response(stmt_handle i32, tx_handle i32, xsqlda XSQLDA) ![][]Value {
	mut b := p.receive_packets(4)!
	for parse_big_endian_i32(b) == op_dummy {
		b = p.receive_packets(4)!
	}

	for parse_big_endian_i32(b) == op_response && p.lazy_response_count > 0 {
		p.lazy_response_count--
		p.parse_generic_response()!
		b = p.receive_packets(4)!
	}

	if parse_big_endian_i32(b) != op_fetch_response {
		if parse_big_endian_i32(b) == op_response {
			p.parse_generic_response()!
		}
		return error(format_error_message('parse_fetch_response internal error'))
	}

	b = p.receive_packets(8)!
	mut status := parse_big_endian_i32(b[..4])
	mut count := parse_big_endian_i32(b[4..])
	mut rows := [][]Value{}

	for count > 0 {
		mut row := []Value{len: xsqlda.vars.len, init: Value(Null{})}
		big256 := big.integer_from_i64(256)
		mut n := (i32(xsqlda.vars.len) + 7) / 8 // Thanks https://github.com/mrotteveel https://github.com/FirebirdSQL/firebird-documentation/issues/216#issuecomment-2788453130

		mut null_indicator := big.integer_from_i64(0)
		b = p.receive_aligned_packets(n)!
		for n = i32(b.len); n > 0; n-- {
			null_indicator = null_indicator * big256 + big.integer_from_i64(b[n - 1])
		}

		for i := 0; i < xsqlda.vars.len; i++ {
			if null_indicator.get_bit(u32(i)) {
				continue
			}
			x := xsqlda.vars[i]
			mut len := i32(0)
			if x.io_length() < 0 {
				b = p.receive_packets(4)!
				len = parse_big_endian_i32(b)
			} else {
				len = i32(x.io_length())
			}

			raw_value := p.receive_aligned_packets(len)!
			println('raw_value: ${raw_value}')
			row[i] = x.get_value(raw_value, p.timezone, p.charset)!
		}

		rows = arrays.concat(rows, row)

		b = p.receive_packets(12)!
		// op := parse_big_endian_i32(b[..4]) // 66 (op_fetch_response)
		status = parse_big_endian_i32(b[4..8])
		count = parse_big_endian_i32(b[8..])
	}

	// Status is 100 after the last row is fetched
	if status != 100 {
		// TODO handle more data
		println('more data must be fetched')
	}

	return rows
}

fn (mut p WireProtocol) free_statement(stmt_handle i32, mode i32) ! {
	p.pack_i32(op_free_statement)
	p.pack_i32(stmt_handle)
	p.pack_i32(mode)
	p.send_packets()!
}

// TODO op_cancel
