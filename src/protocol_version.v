module firebird

import arrays

fn build_protocol(protocol_version i32, architecture_type i32, minimum_type i32, maximum_type i32, preference_weight i32) []u8 {
	mut res := []u8{}
	res = arrays.append(res, marshal_i32(protocol_version))
	res = arrays.append(res, marshal_i32(architecture_type))
	res = arrays.append(res, marshal_i32(minimum_type))
	res = arrays.append(res, marshal_i32(maximum_type))
	res = arrays.append(res, marshal_i32(preference_weight))
	return res
}

const protocol_version_18 = build_protocol(18, 1, 0, 5, 1)
const protocol_version_19 = build_protocol(19, 1, 0, 5, 1)
