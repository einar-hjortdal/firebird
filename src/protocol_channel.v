module firebird

import io
import crypto.cipher
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
	conn          net.TcpConn
	reader        &io.BufferedReader
	writer        &io.BufferedWriter
	plugin        string
	crypto_reader &cipher.Stream
	crypto_writer &cipher.Stream
}

fn new_wire_channel(conn net.TcpConn) &WireChannel {
	new_reader := io.new_buffered_reader(reader: conn)
	new_writer := io.new_buffered_writer(writer: conn)
	wire_channel := &WireChannel{
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
	if plugin == 'Arc4' {
		return error(arc4_error)
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
			return error(arc4_error)
		}

		if c.plugin == 'ChaCha' {
			c.crypto_reader.xor_key_stream(mut buf, src[0..n])
		}

		return n
	}

	return c.reader.read(mut buf)
}

fn (mut c WireChannel) write(buf []u8) !int {
	if c.plugin != '' {
		mut dst := []u8{}
		if c.plugin == 'Arc4' {
			return error(arc4_error)
		}

		if c.plugin == 'ChaCha' {
			c.crypto_writer.xor_key_stream(mut dst, buf)
		}

		mut written := 0
		for written < buf.len {
			written += c.writer.write(dst[written..])!
		}
		return written
	}

	return c.writer.write(mut buf)
}

fn (mut c WireChannel) flush() ! {
	c.writer.flush()!
}

fn (mut c WireChannel) close() ! {
	c.conn.close()!
}
