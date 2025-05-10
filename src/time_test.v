module firebird

import time

fn test_to_blr_date() {
	selected_date := time.parse_iso8601('2020-04-05')!
	date, _ := new_date(selected_date).to_blr()!
	assert date == [u8(0), 0, 230, 64]
}
