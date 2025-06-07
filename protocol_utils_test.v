module firebird

fn test_f64_to_blr() {
	blr, value := f64_to_blr(f64(3.14))
	assert blr == [u8(27)]
	assert value == [u8(64), 9, 30, 184, 81, 235, 133, 31]
}
