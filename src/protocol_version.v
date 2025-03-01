module firebird

import arrays

// https://www.firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-databases-attach-identification
fn build_protocol(protocol_version i32, architecture_type i32, minimum_type i32, maximum_type i32, preference_weight i32) []u8 {
	mut res := []u8{}
	res = arrays.append(res, marshal_i32(fb_protocol_flag | protocol_version))
	res = arrays.append(res, marshal_i32(architecture_type))
	res = arrays.append(res, marshal_i32(minimum_type))
	res = arrays.append(res, marshal_i32(maximum_type))
	res = arrays.append(res, marshal_i32(preference_weight))
	return res
}

// https://github.com/FirebirdSQL/jaybird/blob/master/src/main/org/firebirdsql/gds/impl/wire/WireProtocolConstants.java#L183
const protocol_version_18 = build_protocol(18, 1, 0, 5, 20)

const supported_protocols = [protocol_version_18]

const supported_protocols_count = i32(supported_protocols.len)

fn supported_protocols_to_bytes() []u8 {
	mut res := []u8{}
	for p in supported_protocols {
		res = arrays.append(res, p)
	}
	return res
}

const supported_protocols_bytes = supported_protocols_to_bytes()
