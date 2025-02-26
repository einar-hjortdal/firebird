module firebird

import arrays

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-attach-identification
fn build_protocol(protocol_version i32, architecture_type i32, minimum_type i32, maximum_type i32, preference_weight i32) []u8 {
	mut res := []u8{}
	res = arrays.append(res, marshal_i32(protocol_version))
	res = arrays.append(res, marshal_i32(architecture_type))
	res = arrays.append(res, marshal_i32(minimum_type))
	res = arrays.append(res, marshal_i32(maximum_type))
	res = arrays.append(res, marshal_i32(preference_weight))
	return res
}

const protocol_version_18 = build_protocol(18, 1, 0, 5, 2)
const protocol_version_19 = build_protocol(19, 1, 0, 5, 4)
const supported_protocols = [protocol_version_18, protocol_version_19]

fn supported_protocols_to_bytes() []u8 {
	mut res := []u8{}
	for p in supported_protocols {
		res = arrays.append(res, p)
	}
	return res
}

const supported_protocols_bytes = supported_protocols_to_bytes()
