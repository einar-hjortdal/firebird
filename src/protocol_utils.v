module firebird

import arrays

fn marshal_i32(n i32) []u8 {
	return [
		u8((n >> 24) & 0xFF),
		u8((n >> 16) & 0xFF),
		u8((n >> 8) & 0xFF),
		u8(n & 0xFF),
	]
}

fn marshal_array_u8(au []u8) []u8 {
	// determine the amount of padding needed to have the length of the result be a multiple of 4
	get_padding := fn (length_of_array int) []u8 {
		remainder := length_of_array % 4
		if remainder == 0 {
			return []u8{}
		}

		mut res := []u8{}
		for i := 0; i < remainder; i++ {
			res << u8(0)
		}
		return res
	}

	len := i32(au.len)
	padding := get_padding(len)

	marshalled_len := marshal_i32(len)
	intermediate := arrays.append(marshalled_len, au)
	return arrays.append(intermediate, padding)
}
