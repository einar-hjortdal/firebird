module firebird

import time

fn test_to_blr_date() {
	selected_date := time.parse_iso8601('2020-04-05')!
	_, d := new_date(selected_date).to_blr()!
	assert d == [u8(0), 0, 230, 64]
}

fn test_to_blr_time() {
	selected_time := time.parse_iso8601('2020-04-05T14:30:15')!
	_, t := new_time(selected_time).to_blr()!
	assert t == [u8(31), 31, 96, 112]
}
