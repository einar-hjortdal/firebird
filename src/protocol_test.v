module firebird

fn test_marshal_i32_positive() {
	i32_positive := i32(305419896)
	expected := [u8(18), 52, 86, 120]

	res := marshal_i32(i32_positive)

	assert res == expected
}

fn test_marshal_i32_negative() {
	i32_positive := i32(-305419896)
	expected := [u8(237), 203, 169, 136]

	res := marshal_i32(i32_positive)

	assert res == expected
}
