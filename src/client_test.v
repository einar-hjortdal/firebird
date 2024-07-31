module firebird

import encoding.hex
import math.big
import arrays
import net

fn identify() []u8 {
	random_big_int := big.integer_from_int(9860)
	mut res := []u8{}
	res = arrays.append(res, marshal_i32(op_connect))
	res = arrays.append(res, marshal_i32(op_attach))
	res = arrays.append(res, marshal_i32(3)) // CONNECT_VERSION3
	res = arrays.append(res, marshal_i32(1)) // GENERIC
	res = arrays.append(res, 'devdb'.bytes()) // Database path or alias
	res = arrays.append(res, marshal_i32(1)) // Count of protocol versions understood
	res = arrays.append(res, marshal_array_u8(user_identification('devusr', 'Srp256',
		true, random_big_int)))
	res = arrays.append(res, protocol_version_18)
	return res
}

fn test_conn() {
	hex_bytes := hex.decode('E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7') or {
		panic(err)
	}
	hex_string := hex_bytes.bytestr()
	println(hex_string)

	mut conn := net.dial_tcp('localhost:3050') or { panic(err) }

	identify_data := identify()
	written := conn.write(identify_data) or { panic(err) }

	mut buffer := []u8{cap: 255}
	response := conn.read(mut buffer) or { panic(err) } // times out here.
	// The server seems to not respond, and does not drop the connection either.const
	// Does the server only respond to valid requests?
	println(response)
	println(buffer.bytestr())
}
