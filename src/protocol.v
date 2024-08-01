module firebird

import arrays
import os
import io
import math.big
// import crypto.cipher
import x.crypto.chacha20
import crypto.sha256
import net

const plugin_list = 'Srp256,Srp'
const buffer_len = 1024
const max_char_length = 32767
const blob_segment_size = 32000

const low_priority_todo = 'https://github.com/Coachonko/firebird/blob/pending/TODO.md#low-priority'
const legacy_auth_error = 'LegacyAuth is not supported: ${low_priority_todo}'
const arc4_error = 'Arc4 wire encryption plugin is not supported: ${low_priority_todo}'

struct WireChannel {
mut:
	conn   net.TcpConn
	reader &io.BufferedReader
	// The firebird protocol expects that we are in control of when the writing is flushed.
	// In some situations it is required that flushing is deferred.
	// io.BufferedWriter doesn't exist
	// https://github.com/vlang/v/issues/21975
	// writer         &io.BufferedWriter
	plugin string
	// crypto_reader and crypto_writer should implement cipher.Stream
	// This allows to use any supported stream cipher
	// chacha20.Cipher and rc4.Cipher implement the cipher.Stream interface wrong.
	// https://github.com/vlang/v/issues/21973
	crypto_reader &chacha20.Cipher // &cipher.Stream
	crypto_writer &chacha20.Cipher // &cipher.Stream
}

fn new_wire_channel(conn net.TcpConn) &WireChannel {
	new_reader := io.new_buffered_reader(reader: conn)
	// new_writer :=
	wire_channel := &WireChannel{
		conn: conn
		reader: new_reader
		// writer: new_writer
		crypto_reader: unsafe { nil }
		crypto_writer: unsafe { nil }
	}
	return wire_channel
}

fn (mut c WireChannel) set_crypt_key(plugin string, session_key []u8, nonce []u8) ! {
	c.plugin = plugin
	if plugin == 'Arc4' {
		return error(firebird.arc4_error)
	}

	if plugin == 'ChaCha' {
		mut digest := sha256.new()
		digest.write(session_key)!
		key := digest.sum([]u8{})
		c.crypto_reader = chacha20.new_cipher(key, nonce)!
		c.crypto_writer = chacha20.new_cipher(key, nonce)!
	}

	return error('Unknown wire encryption plugin name: ${plugin}')
}

fn (mut c WireChannel) read(mut buf []u8) !int {
	if c.plugin != '' {
		mut src := []u8{}
		n := c.reader.read(mut src)!
		if c.plugin == 'Arc4' {
			return error(firebird.arc4_error)
		}

		if c.plugin == 'ChaCha' {
			c.crypto_reader.xor_key_stream(mut buf, src[0..n])
		}

		return n
	}

	return c.reader.read(mut buf)
}

fn (mut c WireChannel) write(buf []u8) !int {
	return c.conn.write(buf)!
}

// fn (mut c WireChannel) write(buf []u8) !int {
// 	if c.plugin != '' {
// 		mut dst := []u8{}
// 		if c.plugin == 'Arc4' {
// 			return error(firebird.arc4_error)
// 		}

// 		if c.plugin == 'ChaCha' {
// 			c.crypto_writer.xor_key_stream(mut dst, buf)
// 		}

// 		mut written := 0
// 		for written < buf.len {
// 			written += c.writer.write(dst[written..])!
// 		}
// 		return written
// 	}

// 	return c.writer.write(mut buf)
// }

// fn (mut c WireChannel) flush() ! {
// 	c.writer.flush()!
// }

fn (mut c WireChannel) close() ! {
	c.conn.close()!
}

struct WireProtocol {
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

fn user_identification(user string, auth_plugin_name string, wire_crypt bool, client_public big.Integer) []u8 {
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
			panic(firebird.legacy_auth_error)
		}
		panic('Unknown plugin name: ${auth_plugin_name}')
	}

	user_name_bytes := user.to_upper().bytes()
	user_name := arrays.append([u8(cnct_login), u8(user_name_bytes.len)], user_name_bytes)

	plugin_name_bytes := auth_plugin_name.bytes()
	plugin_name := arrays.append([u8(cnct_plugin_name), u8(plugin_name_bytes.len)], plugin_name_bytes)

	plugins_bytes := firebird.plugin_list.bytes()
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
