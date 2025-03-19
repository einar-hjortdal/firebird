module firebird

import crypto.cipher
import crypto.sha256
import io
import net
import x.crypto.chacha20

const max_char_length = 32767
const blob_segment_size = 32000

const low_priority_todo = 'https://github.com/einar-hjortdal/firebird/blob/pending/TODO.md#low-priority'
const legacy_auth_error = 'LegacyAuth is not supported: ${low_priority_todo}'
const arc4_error = 'Arc4 wire encryption plugin is not supported: ${low_priority_todo}'

struct WireChannel {
mut:
	conn          net.TcpConn
	reader        io.BufferedReader
	writer        io.BufferedWriter
	plugin        string
	crypto_reader cipher.Stream
	crypto_writer cipher.Stream
}

fn new_wire_channel(conn net.TcpConn) WireChannel {
	brc := io.BufferedReaderConfig{
		reader: conn
	}
	bwc := io.BufferedWriterConfig{
		writer: conn
	}
	new_reader := io.new_buffered_reader(brc)
	new_writer := io.new_buffered_writer(bwc) or { panic(err) } // Will never panic because cap is not 0 (uses default cap)
	wire_channel := WireChannel{
		conn:          conn
		reader:        new_reader
		writer:        new_writer
		crypto_reader: unsafe { nil }
		crypto_writer: unsafe { nil }
	}
	return wire_channel
}

fn (mut c WireChannel) set_crypt_key(plugin string, session_key []u8, nonce []u8) ! {
	c.plugin = plugin
	match plugin {
		'Arc4' {
			return error(arc4_error)
		}
		'ChaCha64' {
			return error(format_error_message('ChaCha64 not supported yet')) // TODO handle ChaCha64, not available in vlib yet
		}
		'ChaCha' {
			mut digest := sha256.new()
			digest.write(session_key)!
			key := digest.sum([]u8{})
			c.crypto_reader = chacha20.new_cipher(key, nonce)!
			c.crypto_writer = chacha20.new_cipher(key, nonce)!
		}
		else {
			return error(format_error_message('Unknown wire encryption plugin name: ${plugin}'))
		}
	}
}

fn (mut c WireChannel) read(mut buf []u8) !int {
	if c.plugin == '' {
		return c.reader.read(mut buf)!
	}

	mut src := []u8{len: buf.len}
	read := c.reader.read(mut src)!
	c.crypto_reader.xor_key_stream(mut buf, src[..read])
	// println(src)
	// println(buf)
	// Looks like the second call of xor_key_stream fails to decode the data
	return read
}

fn (mut c WireChannel) write(buf []u8) !int {
	if c.plugin == '' {
		return c.writer.write(buf)!
	}

	mut dst := []u8{len: buf.len}
	c.crypto_writer.xor_key_stream(mut dst, buf)
	mut written := 0
	for written < buf.len {
		written += c.writer.write(dst[written..])!
	}
	return written
}

fn (mut c WireChannel) flush() ! {
	c.writer.flush()!
}

fn (mut c WireChannel) close() ! {
	c.conn.close()!
}
