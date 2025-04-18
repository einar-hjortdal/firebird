module firebird

import arrays
import time

// Because the time module in vlib does not contain functions to handle timezones, timezone data obtained
// from a firebird database is given to users separate from timestamps.
// A firebird timestamp may be either name-based or offset-based.
// A name-based timezone has a string that represents the time zone.
// An offset-based timezone has a number that represents the amount of minutes of displacement.
pub struct Time {
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
	if t.timestamp.year == 0 {
		if t.named_zone != '' || t.offset != 0 {
			blr := t.to_blr_time_tz()!
			return blr, u8(blr_sql_time_tz)
		}
		blr := t.to_blr_time()
		value := u8(blr_sql_time)
		return blr, value
	}

	if t.named_zone != '' || t.offset != 0 {
		blr := t.to_blr_timestamp_tz()!
		return blr, u8(blr_timestamp_tz)
	}
	blr := t.to_blr_timestamp()
	value := u8(blr_timestamp)
	return blr, value
}
