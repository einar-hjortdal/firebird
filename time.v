module firebird

import arrays
import encoding.binary
import time

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/common/TimeZoneUtil.cpp#L302
const one_day = 24 * 60 - 1

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/common/TimeZoneUtil.cpp#L1144
fn is_offset(time_zone u16) bool {
	return time_zone <= one_day * 2
}

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/common/TimeZoneUtil.cpp#L1164
fn decode_offset(time_zone u16) i16 {
	return i16(time_zone) - one_day
}

fn encode_offset(offset i16) i16 {
	return offset + one_day
}

// used to validate user-provided offset
fn validate_offset(o i16) ! {
	if o == 0 || !is_offset(u16(o)) {
		return new_error('invalid offset')
	}
}

fn validate_named_zone(n string) !u16 {
	// this is inefficient: reverse-lookup of map[int]string with string comparison
	for k, v in timezones {
		if v == n {
			return u16(k)
		}
	}
	return new_error('invalid named_zone')
}

// `DateTime` embeds `time.Time`.
// To initialize a new DateTime struct, utilize one of its factory functions.
// Because the time module in vlib does not contain functions to handle timezones, timezone data obtained
// from a firebird database is given to users separate from timestamps.
// A firebird timestamp may be either name-based or offset-based.
// A name-based timezone has a string that represents the time zone.
// An offset-based timezone has a number that represents the amount of minutes of displacement.
pub struct DateTime {
	time.Time
	sql_type       int
	named_zone_key u16
pub:
	offset     i16
	named_zone string
}

pub fn new_date(t time.Time) DateTime {
	return DateTime{
		Time:     t
		sql_type: sql_type_date
	}
}

pub fn new_time(t time.Time) DateTime {
	return DateTime{
		Time:     t
		sql_type: sql_type_time
	}
}

fn new_time_tz(t time.Time, offset i16, named_zone string, named_zone_key u16) DateTime {
	return DateTime{
		Time:           t
		sql_type:       sql_type_time_tz
		offset:         offset
		named_zone:     named_zone
		named_zone_key: named_zone_key
	}
}

pub fn new_time_tz_offset(t time.Time, offset i16) !DateTime {
	validate_offset(offset)!
	return new_time_tz(t, offset, '', 0)
}

pub fn new_time_tz_named_zone(t time.Time, named_zone string) !DateTime {
	named_zone_key := validate_named_zone(named_zone)!
	return new_time_tz(t, 0, named_zone, named_zone_key)
}

pub fn new_timestamp(t time.Time) DateTime {
	return DateTime{
		Time:     t
		sql_type: sql_type_timestamp
	}
}

fn new_timestamp_tz(t time.Time, offset i16, named_zone string, named_zone_key u16) DateTime {
	return DateTime{
		Time:           t
		sql_type:       sql_type_timestamp_tz
		offset:         offset
		named_zone:     named_zone
		named_zone_key: named_zone_key
	}
}

pub fn new_timestamp_tz_offset(t time.Time, offset i16) !DateTime {
	validate_offset(offset)!
	return new_timestamp_tz(t, offset, '', 0)
}

pub fn new_timestamp_tz_named_zone(t time.Time, named_zone string) !DateTime {
	named_zone_key := validate_named_zone(named_zone)!
	return new_timestamp_tz(t, 0, named_zone, named_zone_key)
}

// returns year, month, day
// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/common/classes/NoThrowTimeStamp.cpp#L178
fn get_date(raw_value []u8) (int, int, int) {
	mut nday := parse_big_endian_i32(raw_value) + 678882
	century := 4 * nday / 146097
	nday = 4 * nday - 1 - 146097 * century
	mut day := nday / 4

	nday = (4 * day + 3) / 1461
	day = 4 * day + 3 - 1461 * nday
	day = (day + 4) / 4

	mut month := (5 * day - 3) / 153
	day = 5 * day - 3 - 153 * month
	day = (day + 5) / 5

	mut year := 100 * century + nday
	if month < 10 {
		month += 3
	} else {
		month -= 9
		year++
	}
	return year, month, day
}

// returns hours, minutes, seconds and fractions
// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/common/classes/NoThrowTimeStamp.cpp#L260
fn get_time(raw_value []u8) (int, int, int, int) {
	mut n := parse_big_endian_i32(raw_value)
	h := n / (3600 * isc_time_seconds_precision)
	n %= 3600 * isc_time_seconds_precision
	m := n / (60 * isc_time_seconds_precision)
	n %= 60 * isc_time_seconds_precision
	s := n / isc_time_seconds_precision
	f := n % isc_time_seconds_precision
	return h, m, s, f
}

// TODO when parsing named_zones, named_zone_key is also needed
fn get_default_named_zone(named_zone string) !(u16, string) {
	if named_zone == '' {
		return max_u16, timezones[max_u16]
	}
	for k, v in timezones {
		if v == named_zone {
			return u16(k), named_zone
		}
	}
	return new_error('invalid named_zone')
}

fn parse_date(raw_value []u8, named_zone string) !DateTime {
	year, month, day := get_date(raw_value[..4])
	timestamp := time.parse_iso8601('${year}-${month}-${day}')!
	k, v := get_default_named_zone(named_zone)!
	return DateTime{
		Time:           timestamp
		sql_type:       sql_type_date
		named_zone_key: k
		named_zone:     v
	}
}

fn parse_time(raw_value []u8, named_zone string) !DateTime {
	hours, minutes, seconds, fractions := get_time(raw_value[..4])
	now := time.now()
	timestamp :=
		time.parse_iso8601('${now.year}-${now.month}-${now.day}T${hours}:${minutes}:${seconds}.${fractions}')!
	k, v := get_default_named_zone(named_zone)!
	return DateTime{
		Time:           timestamp
		sql_type:       sql_type_time
		named_zone_key: k
		named_zone:     v
	}
}

fn parse_time_tz(raw_value []u8) !DateTime {
	hours, minutes, seconds, fractions := get_time(raw_value[..4])
	now := time.now()
	timestamp :=
		time.parse_iso8601('${now.year}-${now.month}-${now.day}T${hours}:${minutes}:${seconds}.${fractions}')!

	// TODO what is this for? It is always 0 when is_offset and always max_u16 when named_zone
	// timezone := binary.big_endian_u16(raw_value[4..6])
	offset := binary.big_endian_u16(raw_value[6..8])
	if is_offset(offset) {
		return DateTime{
			Time:     timestamp
			sql_type: sql_type_time_tz
			offset:   decode_offset(offset)
		}
	}

	return DateTime{
		Time:       timestamp
		sql_type:   sql_type_time_tz
		named_zone: timezones[offset]
	}
}

fn parse_timestamp(raw_value []u8, named_zone string) !DateTime {
	year, month, day := get_date(raw_value[..4])
	hours, minutes, seconds, fractions := get_time(raw_value[4..8])
	timestamp :=
		time.parse_iso8601('${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${fractions}')!
	k, v := get_default_named_zone(named_zone)!
	return DateTime{
		Time:           timestamp
		sql_type:       sql_type_timestamp
		named_zone_key: k
		named_zone:     v
	}
}

fn parse_timestamp_tz(raw_value []u8) !DateTime {
	year, month, day := get_date(raw_value[..4])
	hours, minutes, seconds, fractions := get_time(raw_value[4..8])
	timestamp :=
		time.parse_iso8601('${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${fractions}')!

	// timezone := binary.big_endian_u16(raw_value[8..10])
	offset := binary.big_endian_u16(raw_value[10..12])
	if is_offset(offset) {
		return DateTime{
			Time:     timestamp
			sql_type: sql_type_timestamp_tz
			offset:   decode_offset(offset)
		}
	}

	return DateTime{
		Time:       timestamp
		sql_type:   sql_type_timestamp_tz
		named_zone: timezones[offset]
	}
}

fn (t DateTime) to_blr_time() []u8 {
	hours := t.hour * 3600
	minutes := t.minute * 60
	seconds := t.second
	fractions := t.nanosecond / 100_000
	return marshal_i32_big_endian(i32((hours + minutes + seconds) * 10_000 + fractions))
}

fn (t DateTime) get_timezone() ![]u8 {
	if t.named_zone_key != 0 {
		first_u8_pair := marshal_u16_big_endian(max_u16)
		second_u8_pair := marshal_u16_big_endian(t.named_zone_key)
		return arrays.append(first_u8_pair, second_u8_pair)
	}
	first_u8_pair := marshal_i16_big_endian(0)
	second_u8_pair := marshal_i16_big_endian(encode_offset(t.offset))
	return arrays.append(first_u8_pair, second_u8_pair)
}

fn (t DateTime) to_blr_time_tz() ![]u8 {
	time_segment := t.to_blr_time()
	tz_segment := t.get_timezone()!
	return arrays.append(time_segment, tz_segment)
}

// Firebird uses a modified Julian date
fn (t DateTime) to_blr_date() []u8 {
	julian_month := (t.month + 9) % 12
	intermediate_year := t.year + ((t.month + 9) / 12) - 1
	century := intermediate_year / 100
	julian_year := intermediate_year - 100 * century
	modified_julian_date := (146_097 * century) / 4 + (1461 * julian_year) / 4 +
		(153 * julian_month + 2) / 5 + t.day - 678_882
	return marshal_i32_big_endian(i32(modified_julian_date))
}

fn (t DateTime) to_blr_timestamp() []u8 {
	time_segment := t.to_blr_time()
	date_segment := t.to_blr_date()
	return arrays.append(date_segment, time_segment)
}

fn (t DateTime) to_blr_timestamp_tz() ![]u8 {
	timestamp_segment := t.to_blr_timestamp()
	timezone_segment := t.get_timezone()!
	return arrays.append(timestamp_segment, timezone_segment)
}

fn (t DateTime) to_blr() !([]u8, []u8) {
	match t.sql_type {
		sql_type_date {
			value := t.to_blr_date()
			blr := [u8(blr_sql_date)]
			return blr, value
		}
		sql_type_time {
			value := t.to_blr_time()
			blr := [u8(blr_sql_time)]
			return blr, value
		}
		sql_type_time_tz {
			value := t.to_blr_time_tz()!
			blr := [u8(blr_sql_time_tz)]
			return blr, value
		}
		sql_type_timestamp {
			value := t.to_blr_timestamp()
			blr := [u8(blr_timestamp)]
			return blr, value
		}
		sql_type_timestamp_tz {
			value := t.to_blr_timestamp_tz()!
			blr := [u8(blr_timestamp_tz)]
			return blr, value
		}
		else {
			return new_error('invalid DateTime.sql_type')
		}
	}
}
