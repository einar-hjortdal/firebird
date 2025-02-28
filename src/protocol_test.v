module firebird

fn test_marshal_i32_positive() {
	integer := 305419896
	i32_positive := i32(integer)
	expected := [u8(18), 52, 86, 120]

	res := marshal_i32(i32_positive)

	assert res == expected
}
