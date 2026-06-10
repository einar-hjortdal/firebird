module tests

import time
import firebird
import test_utils

fn testsuite_begin() ! {
	test_utils.container_firebird_start()!
}

fn testsuite_end() ! {
	test_utils.container_firebird_clean()
}

fn test_statement_time_params() {
	mut conn := new_connection()!

	mut tx := start_transaction(mut conn)!
	tx.execute('CREATE TABLE foo (
		id INTEGER PRIMARY KEY,
		a DATE,
		b TIME,
		c TIME WITH TIME ZONE,
		d TIMESTAMP,
		e TIMESTAMP WITH TIME ZONE
		)')!
	tx.commit()!

	tx = start_transaction(mut conn)!

	// string params
	tx.execute('INSERT INTO foo (id, a) VALUES (?, ?)', i32(1), '2025-02-12')!
	tx.execute('INSERT INTO foo (id, b) VALUES (?, ?)', i32(2), '12:34:56')!
	tx.execute('INSERT INTO foo (id, c) VALUES (?, ?)', i32(3), '12:34:56 +02:00')!
	tx.execute('INSERT INTO foo (id, d) VALUES (?, ?)', i32(4), '2025-02-12 12:34:56')!
	tx.execute('INSERT INTO foo (id, e) VALUES (?, ?)', i32(5),
		'2025-02-12 12:34:56 Europe/Brussels')!

	// same data, but as DateTime objects
	d := firebird.new_date(time.parse_iso8601('2025-02-12')!)
	tx.execute('INSERT INTO foo (id, a) VALUES (?, ?)', i32(6), d)!

	t := firebird.new_time(time.parse_iso8601('2025-02-12T12:34:56')!)
	tx.execute('INSERT INTO foo (id, b) VALUES (?, ?)', i32(7), t)!

	t_tz := firebird.new_time_tz_offset(time.parse_iso8601('2025-02-12T12:34:56')!, 120)!
	tx.execute('INSERT INTO foo (id, c) VALUES (?, ?)', i32(8), t_tz)!

	ts := firebird.new_timestamp(time.parse_iso8601('2025-02-12T12:34:56Z')!)
	tx.execute('INSERT INTO foo (id, d) VALUES (?, ?)', i32(9), ts)!

	ts_tz := firebird.new_timestamp_tz_named_zone(time.parse_iso8601('2025-02-12T12:34:56Z')!,
		'Europe/Brussels')!
	tx.execute('INSERT INTO foo (id, e) VALUES (?, ?)', i32(10), ts_tz)!

	result := tx.execute('SELECT * FROM foo')!
	rows := result.rows()
	assert rows.len == 10

	mut id_string, _ := rows[0].values()[0].get_i32()!
	mut id_date_time, _ := rows[5].values()[0].get_i32()!
	mut v_string, _ := rows[0].values()[1].get_date_time()!
	mut v_date_time, _ := rows[5].values()[1].get_date_time()!

	assert id_string == 1
	assert id_date_time == 6
	assert v_string.Time.year == 2025
	assert v_date_time.Time.year == 2025
	assert v_string.Time.month == 2
	assert v_date_time.Time.month == 2
	assert v_string.Time.day == 12
	assert v_date_time.Time.day == 12

	id_string, _ = rows[1].values()[0].get_i32()!
	id_date_time, _ = rows[6].values()[0].get_i32()!
	v_string, _ = rows[1].values()[2].get_date_time()!
	v_date_time, _ = rows[6].values()[2].get_date_time()!

	assert id_string == 2
	assert id_date_time == 7
	assert v_string.Time.hour == 12
	assert v_date_time.Time.hour == 12
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56

	id_string, _ = rows[2].values()[0].get_i32()!
	id_date_time, _ = rows[7].values()[0].get_i32()!
	v_string, _ = rows[2].values()[3].get_date_time()!
	v_date_time, _ = rows[7].values()[3].get_date_time()!

	assert id_string == 3
	assert id_date_time == 8
	assert v_string.Time.hour == 10
	// When a timestamp is inserted in Firebird as DateTime, the offset is not added to Time.time
	assert v_date_time.Time.hour == 12
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56
	assert v_string.offset == 120
	assert v_date_time.offset == 120

	id_string, _ = rows[3].values()[0].get_i32()!
	id_date_time, _ = rows[8].values()[0].get_i32()!
	v_string, _ = rows[3].values()[4].get_date_time()!
	v_date_time, _ = rows[8].values()[4].get_date_time()!

	assert id_string == 4
	assert id_date_time == 9
	assert v_string.Time.year == 2025
	assert v_date_time.Time.year == 2025
	assert v_string.Time.month == 2
	assert v_date_time.Time.month == 2
	assert v_string.Time.day == 12
	assert v_date_time.Time.day == 12
	assert v_string.Time.hour == 12
	assert v_date_time.Time.hour == 12
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56

	id_string, _ = rows[4].values()[0].get_i32()!
	id_date_time, _ = rows[9].values()[0].get_i32()!
	v_string, _ = rows[4].values()[5].get_date_time()!
	v_date_time, _ = rows[9].values()[5].get_date_time()!

	assert id_string == 5
	assert id_date_time == 10
	assert v_string.Time.year == 2025
	assert v_date_time.Time.year == 2025
	assert v_string.Time.month == 2
	assert v_date_time.Time.month == 2
	assert v_string.Time.day == 12
	assert v_date_time.Time.day == 12
	// Hour is not checked because named_zone behavior may change?
	assert v_string.Time.minute == 34
	assert v_date_time.Time.minute == 34
	assert v_string.Time.second == 56
	assert v_date_time.Time.second == 56
	assert v_string.named_zone == 'Europe/Brussels'
	assert v_date_time.named_zone == 'Europe/Brussels'

	tx.rollback()!

	tx = start_transaction(mut conn)!
	tx.execute('DROP TABLE foo')!
	tx.commit()!
	conn.close()!
}

