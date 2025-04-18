module firebird

import arrays
import encoding.binary
import time

// Because the time module in vlib does not contain functions to handle timezones, timezone data obtained
// from a firebird database is given to users separate from timestamps.
// sql_type must be one of the following:
// sql_type_time
// sql_type_date
// sql_type_timestamp
// sql_type_timestamp_tz
// sql_type_time_tz
// sql_type_timestamp_tz_ex (currently unsupported, see https://github.com/einar-hjortdal/firebird/blob/pending/TODO.md#low-priority)
// sql_type_time_tz_ex (currently unsupported, see https://github.com/einar-hjortdal/firebird/blob/pending/TODO.md#low-priority)
// A firebird timestamp may be either name-based or offset-based.
// A name-based timezone has a string that represents the time zone.
// An offset-based timezone has a number that represents the amount of minutes of displacement.
pub struct Time {
	sql_type   int
	timestamp  time.Time
	offset     i16
	named_zone string
}

pub fn (t Time) timestamp() time.Time {
	return t.timestamp
}

pub fn (t Time) offset() i16 {
	return t.offset
}

pub fn (t Time) named_zone() string {
	return t.named_zone
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

fn get_default_timezone(timezone string) string {
	if timezone == '' {
		return timezones[max_u16]
	}
	return timezone
}

fn parse_date(raw_value []u8, timezone string) !Time {
	year, month, day := get_date(raw_value[..4])
	timestamp := time.parse_iso8601('${year}-${month}-${day}')!
	return Time{
		sql_type:   sql_type_date
		timestamp:  timestamp
		named_zone: get_default_timezone(timezone)
	}
}

fn parse_time(raw_value []u8, timezone string) !Time {
	hours, minutes, seconds, fractions := get_time(raw_value[..4])
	now := time.now()
	timestamp := time.parse_iso8601('${now.year}-${now.month}-${now.day}T${hours}:${minutes}:${seconds}.${fractions}')!
	return Time{
		sql_type:   sql_type_time
		timestamp:  timestamp
		named_zone: get_default_timezone(timezone)
	}
}

fn parse_time_tz(raw_value []u8) !Time {
	hours, minutes, seconds, fractions := get_time(raw_value[..4])
	now := time.now()
	timestamp := time.parse_iso8601('${now.year}-${now.month}-${now.day}T${hours}:${minutes}:${seconds}.${fractions}')!

	// TODO what is this for? It is always 0 when is_offset and always max_u16 when named_zone
	// timezone := binary.big_endian_u16(raw_value[4..6])
	offset := binary.big_endian_u16(raw_value[6..8])
	if is_offset(offset) {
		return Time{
			sql_type:  sql_type_time_tz
			timestamp: timestamp
			offset:    decode_offset(offset)
		}
	}

	return Time{
		sql_type:   sql_type_time_tz
		timestamp:  timestamp
		named_zone: timezones[offset]
	}
}

fn parse_timestamp(raw_value []u8, timezone string) !Time {
	year, month, day := get_date(raw_value[..4])
	hours, minutes, seconds, fractions := get_time(raw_value[4..8])
	timestamp := time.parse_iso8601('${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${fractions}')!
	return Time{
		sql_type:   sql_type_timestamp
		timestamp:  timestamp
		named_zone: timezone
	}
}

fn parse_timestamp_tz(raw_value []u8) !Time {
	year, month, day := get_date(raw_value[..4])
	hours, minutes, seconds, fractions := get_time(raw_value[4..8])
	timestamp := time.parse_iso8601('${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${fractions}')!

	// timezone := binary.big_endian_u16(raw_value[8..10])
	offset := binary.big_endian_u16(raw_value[10..12])
	if is_offset(offset) {
		return Time{
			sql_type:  sql_type_timestamp_tz
			timestamp: timestamp
			offset:    decode_offset(offset)
		}
	}

	return Time{
		sql_type:   sql_type_timestamp_tz
		timestamp:  timestamp
		named_zone: timezones[offset]
	}
}

fn (t Time) to_blr_time() []u8 {
	hours := t.timestamp.hour * 3600
	minutes := t.timestamp.minute * 60
	seconds := t.timestamp.second * 10_000
	fractions := t.timestamp.nanosecond / 100_000
	return marshal_i32_big_endian(i32(hours + minutes + seconds + fractions))
}

fn (t Time) get_timezone() ![]u8 {
	if t.named_zone != '' {
		first_u8_pair := marshal_i16_big_endian(i16(max_u16))
		// this is inefficient: reverse-lookup of map[int]string with string comparison
		for k, v in timezones {
			if v == t.named_zone {
				second_u8_pair := marshal_i16_big_endian(i16(k))
				return arrays.append(first_u8_pair, second_u8_pair)
			}
		}
		return error(format_error_message('invalid named_zone'))
	}
	first_u8_pair := marshal_i16_big_endian(0)
	second_u8_pair := marshal_i16_big_endian(t.offset)
	return arrays.append(first_u8_pair, second_u8_pair)
}

fn (t Time) to_blr_time_tz() ![]u8 {
	time_segment := t.to_blr_time()
	tz_segment := t.get_timezone()!
	return arrays.append(time_segment, tz_segment)
}

// Firebird uses a modified Julian date
fn (t Time) to_blr_date() []u8 {
	julian_month := t.timestamp.month + 9 % 12
	intermediate_year := t.timestamp.year + (t.timestamp.month / 12) - 1
	century := intermediate_year / 100
	julian_year := intermediate_year - 100 * century
	modified_julian_date := (146_097 * century) / 4 + (1461 * julian_year) / 4 +
		(153 * julian_month + 2) / 5 + t.timestamp.day - 678_882
	return marshal_i32_big_endian(i32(modified_julian_date))
}

fn (t Time) to_blr_timestamp() []u8 {
	time_segment := t.to_blr_time()
	date_segment := t.to_blr_date()
	return arrays.append(date_segment, time_segment)
}

fn (t Time) to_blr_timestamp_tz() ![]u8 {
	timestamp_segment := t.to_blr_time()
	timezone_segment := t.get_timezone()!
	return arrays.append(timestamp_segment, timezone_segment)
}

fn (t Time) to_blr() !([]u8, u8) {
	match t.sql_type {
		sql_type_date {
			blr := t.to_blr_date()
			value := u8(blr_sql_date)
			return blr, value
		}
		sql_type_time {
			blr := t.to_blr_time()
			value := u8(blr_sql_time)
			return blr, value
		}
		sql_type_time_tz {
			blr := t.to_blr_time_tz()!
			value := u8(blr_sql_time_tz)
			return blr, value
		}
		sql_type_timestamp {
			blr := t.to_blr_timestamp()
			value := u8(blr_timestamp)
			return blr, value
		}
		sql_type_timestamp_tz {
			blr := t.to_blr_timestamp_tz()!
			value := u8(blr_timestamp_tz)
			return blr, value
		}
		else {
			return error(format_error_message('invalid Time.sql_type'))
		}
	}
}
