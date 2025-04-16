module firebird

import encoding.binary
import math
import time

pub const charset_none = 'NONE'
pub const charset_utf8 = 'UTF8'
pub const charset_octets = 'OCTETS'
pub const charset_unicode_fss = 'UNICODE_FSS'

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/include/firebird/impl/sqlda_pub.h#L29
const dsql_close = 1
const dsql_drop = 2
const dsql_unprepare = 4

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/include/firebird/impl/sqlda_pub.h#L67
const sql_type_text = 452
const sql_type_varying = 448
const sql_type_short = 500
const sql_type_long = 496
const sql_type_float = 482
const sql_type_double = 480
const sql_type_d_float = 530
const sql_type_timestamp = 510
const sql_type_blob = 520
const sql_type_array = 540
const sql_type_quad = 550
const sql_type_time = 560
const sql_type_date = 570
const sql_type_int64 = 580
const sql_type_timestamp_tz_ex = 32748 // why not happening? TODO
const sql_type_time_tz_ex = 32750
const sql_type_int128 = 32752
const sql_type_timestamp_tz = 32754
const sql_type_time_tz = 32756
const sql_type_dec64 = 32760
const sql_type_dec128 = 32762
const sql_type_boolean = 32764
const sql_type_null = 32766

const xsqlvar_type_length = {
	sql_type_text:            -1
	sql_type_varying:         -1
	sql_type_short:           4
	sql_type_long:            4
	sql_type_float:           4
	sql_type_time:            4
	sql_type_date:            4
	sql_type_double:          8
	sql_type_timestamp:       8
	sql_type_blob:            8
	sql_type_array:           8
	sql_type_quad:            8
	sql_type_int64:           8
	sql_type_int128:          16
	sql_type_timestamp_tz:    12 // I thought it was 10, but it's 12
	sql_type_timestamp_tz_ex: 12 // TODO this must be larger than 12
	sql_type_time_tz:         8 // I thought it was 6, but it is 8
	sql_type_time_tz_ex:      8 // TODO this must be larger than 8
	sql_type_dec64:           8
	sql_type_dec128:          16
	sql_type_boolean:         1
}

const xsqlvar_type_display_length = {
	sql_type_text:         -1
	sql_type_varying:      -1
	sql_type_short:        6
	sql_type_long:         11
	sql_type_float:        17
	sql_type_time:         11
	sql_type_date:         10
	sql_type_double:       17
	sql_type_timestamp:    22
	sql_type_blob:         0
	sql_type_array:        -1
	sql_type_quad:         20
	sql_type_int64:        20
	sql_type_int128:       20
	sql_type_timestamp_tz: 28
	sql_type_time_tz:      17
	sql_type_dec64:        16
	sql_type_dec128:       34
	sql_type_boolean:      5
}

const xsqlvar_type_name = {
	sql_type_text:         'TEXT'
	sql_type_varying:      'VARYING'
	sql_type_short:        'SHORT'
	sql_type_long:         'LONG'
	sql_type_float:        'FLOAT'
	sql_type_time:         'TIME'
	sql_type_date:         'DATE'
	sql_type_double:       'DOUBLE'
	sql_type_timestamp:    'TIMESTAMP'
	sql_type_blob:         'BLOB'
	sql_type_array:        'ARRAY'
	sql_type_quad:         'QUAD'
	sql_type_int64:        'INT64'
	sql_type_int128:       'INT128'
	sql_type_timestamp_tz: 'TIMESTAMP WITH TIMEZONE'
	sql_type_time_tz:      'TIME WITH TIMEZONE'
	sql_type_dec64:        'DECFLOAT(16)'
	sql_type_dec128:       'DECFLOAT(34)'
	sql_type_boolean:      'BOOLEAN'
}

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

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/jaybird-native/src/main/java/org/firebirdsql/jna/fbclient/XSQLVAR.java#L11
struct XSQLVar {
mut:
	alias_name     string
	field_name     string
	own_name       string
	relation_name  string
	sql_len        i32
	sql_scale      i32
	sql_subtype    i32
	sql_type       i32
	null_indicator bool
}

fn (x XSQLVar) io_length() int {
	if x.sql_type == sql_type_text {
		return x.sql_len
	}
	return xsqlvar_type_length[x.sql_type]
}

fn (x XSQLVar) display_length() int {
	if x.sql_type == sql_type_text || x.sql_type == sql_type_varying {
		return x.sql_len
	}
	return xsqlvar_type_display_length[x.sql_type]
}

fn (x XSQLVar) has_precision_scale() bool {
	return (x.sql_type == sql_type_short || x.sql_type == sql_type_long
		|| x.sql_type == sql_type_quad || x.sql_type == sql_type_int64
		|| x.sql_type == sql_type_int128 || x.sql_type == sql_type_dec64
		|| x.sql_type == sql_type_dec128) && x.sql_scale != 0
}

fn (x XSQLVar) type_name() string {
	return xsqlvar_type_name[x.sql_type]
}

// Because the time module in vlib does not contain functions to handle timezones, timezone data is
// given to the users separate from timestamps.
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
		timestamp:  timestamp
		named_zone: get_default_timezone(timezone)
	}
}

fn parse_time(raw_value []u8, timezone string) !Time {
	hours, minutes, seconds, fractions := get_time(raw_value[..4])
	now := time.now()
	timestamp := time.parse_iso8601('${now.year}-${now.month}-${now.day}T${hours}:${minutes}:${seconds}.${fractions}')!
	return Time{
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
			timestamp: timestamp
			offset:    decode_offset(offset)
		}
	}

	return Time{
		timestamp:  timestamp
		named_zone: timezones[offset]
	}
}

fn parse_timestamp(raw_value []u8, timezone string) !Time {
	year, month, day := get_date(raw_value[..4])
	hours, minutes, seconds, fractions := get_time(raw_value[4..8])
	timestamp := time.parse_iso8601('${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${fractions}')!
	return Time{
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
			timestamp: timestamp
			offset:    decode_offset(offset)
		}
	}

	return Time{
		timestamp:  timestamp
		named_zone: timezones[offset]
	}
}

// https://www.firebirdsql.org/file/documentation/html/en/refdocs/fblangref50/firebird-50-language-reference.html#fblangref50-datatypes-chartypes-unicode
fn (x XSQLVar) parse_string(raw_value []u8, charset string) !Value {
	if x.sql_subtype == 1 {
		return raw_value
	}
	match charset {
		charset_octets, charset_none {
			return raw_value
		}
		charset_unicode_fss, charset_utf8 {
			return raw_value.bytestr()
		}
		else {
			return error(format_error_message('unsupported charset `${charset}`: ${low_priority_todo}'))
		}
	}
}

// TODO eliminate floating point arithmetic
fn (x XSQLVar) parse_short(raw_value []u8) i16 {
	i := parse_big_endian_i16(raw_value)
	if x.sql_scale != 0 {
		return i16(i * i64(math.pow10(x.sql_scale)))
	}
	return i
}

// TODO eliminate floating point arithmetic
fn (x XSQLVar) parse_long(raw_value []u8) i32 {
	i := parse_big_endian_i32(raw_value)
	if x.sql_scale != 0 {
		return i32(i * i64(math.pow10(x.sql_scale)))
	}
	return i
}

// TODO eliminate floating point arithmetic
fn (x XSQLVar) parse_int64(raw_value []u8) i64 {
	i := parse_big_endian_i64(raw_value)
	if x.sql_scale != 0 {
		return i * i64(math.pow10(x.sql_scale))
	}
	return i
}

fn (x XSQLVar) get_value(raw_value []u8, timezone string, charset string) !Value {
	match x.sql_type {
		sql_type_text, sql_type_varying {
			return x.parse_string(raw_value, charset)!
		}
		sql_type_short {
			return x.parse_short(raw_value)
		}
		sql_type_long {
			return x.parse_long(raw_value)
		}
		sql_type_int64 {
			return x.parse_int64(raw_value)
		}
		sql_type_date {
			return parse_date(raw_value, timezone)!
		}
		sql_type_time {
			return parse_time(raw_value, timezone)!
		}
		sql_type_timestamp {
			return parse_timestamp(raw_value, timezone)!
		}
		sql_type_time_tz {
			return parse_time_tz(raw_value)!
		}
		sql_type_timestamp_tz {
			return parse_timestamp_tz(raw_value)!
		}
		sql_type_float {
			return parse_big_endian_f32(raw_value)
		}
		sql_type_double {
			return parse_big_endian_f64(raw_value)
		}
		sql_type_boolean {
			return raw_value[0] != 0
		}
		sql_type_blob {
			return raw_value
		}
		else {
			return error(format_error_message('unsupported data type ${x.sql_type}: ${low_priority_todo}'))
		}
	}
}

struct XSQLDA {
mut:
	vars []XSQLVar
}

fn new_xsqlda(len i32) XSQLDA {
	return XSQLDA{
		vars: []XSQLVar{len: int(len)}
	}
}

fn get_var_data(buf []u8, i int) ([]u8, int) {
	n := i + 2 // first index of data
	l := parse_little_endian_i16(buf[i..n]) // length of data
	e := n + l // last index of data
	v := buf[n..e] // data
	return v, e
}

// TODO refactor loop
fn (mut xsqlda XSQLDA) parse_select_items(buf []u8) !int {
	mut index := 0
	mut i := 0
	for i < buf.len {
		item := buf[i]
		if item == isc_info_end {
			break
		}
		i++ // skip item byte
		match item {
			isc_info_sql_sqlda_seq {
				v, e := get_var_data(buf, i)
				i = e
				index = parse_little_endian_i32(v)
			}
			isc_info_sql_type {
				v, e := get_var_data(buf, i)
				i = e
				mut res := parse_little_endian_i32(v)
				if res % 2 != 0 {
					res--
				}
				xsqlda.vars[index - 1].sql_type = res
			}
			isc_info_sql_sub_type {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].sql_subtype = parse_little_endian_i32(v)
			}
			isc_info_sql_scale {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].sql_scale = parse_little_endian_i32(v)
			}
			isc_info_sql_length {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].sql_len = parse_little_endian_i32(v)
			}
			isc_info_sql_null_ind {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].null_indicator = parse_little_endian_i32(v) != 0
			}
			isc_info_sql_field {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].field_name = v.bytestr()
			}
			isc_info_sql_relation {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].relation_name = v.bytestr()
			}
			isc_info_sql_owner {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].own_name = v.bytestr()
			}
			isc_info_sql_alias {
				v, e := get_var_data(buf, i)
				i = e
				xsqlda.vars[index - 1].alias_name = v.bytestr()
			}
			isc_info_truncated {
				return index // more info at index
			}
			isc_info_sql_describe_end {
				// nothing
			}
			else {
				return error(format_error_message('Unable to parse XSQLDA item'))
			}
		}
	}
	return -1 // no more info
}
