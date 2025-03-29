module firebird

import math
import time
import strings

pub const charset_none = 'NONE'
pub const charset_utf8 = 'UTF8'
pub const charset_octets = 'OCTETS'
pub const charset_unicode_fss = 'UNICODE_FSS'

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
const sql_type_int128 = 32752
const sql_type_timestamp_tz = 32754
const sql_type_time_tz = 32756
const sql_type_dec64 = 32760
const sql_type_dec128 = 32762
const sql_type_boolean = 32764
const sql_type_null = 32766

const xsqlvar_type_length = {
	sql_type_text:         -1
	sql_type_varying:      -1
	sql_type_short:        4
	sql_type_long:         4
	sql_type_float:        4
	sql_type_time:         4
	sql_type_date:         4
	sql_type_double:       8
	sql_type_timestamp:    8
	sql_type_blob:         8
	sql_type_array:        8
	sql_type_quad:         8
	sql_type_int64:        8
	sql_type_int128:       16
	sql_type_timestamp_tz: 10
	sql_type_time_tz:      6
	sql_type_dec64:        8
	sql_type_dec128:       16
	sql_type_boolean:      1
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

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/jaybird-native/src/main/java/org/firebirdsql/jna/fbclient/XSQLVAR.java#L11
struct XSQLVar {
	alias_name  string
	field_name  string
	own_name    string
	rel_name    string
	sql_len     int
	sql_scale   u8
	sql_subtype int
	sql_type    int
	nullable    bool
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

fn (x XSQLVar) parse_timezone(raw_value []u8) {
	// raw_value is i16 big endian
	// vlib time does not have timezone functions
}

fn (x XSQLVar) get_date(raw_value []u8) (int, int, int) {
	return 0, 0, 0 // TODO
}

fn (x XSQLVar) get_time(raw_value []u8) (int, int, int, int) {
	return 0, 0, 0, 0 // TODO
}

fn (x XSQLVar) parse_date(raw_value []u8) time.Time {
	return time.now() // TODO
}

fn (x XSQLVar) parse_time(raw_value []u8) time.Time {
	return time.now() // TODO
}

fn (x XSQLVar) parse_timestamp(raw_value []u8) time.Time {
	return time.now() // TODO
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
fn (x XSQLVar) parse_short(raw_value []u8) Value {
	i := i16(parse_i32(raw_value))
	if x.sql_scale != 0 {
		return i16(i * i64(math.pow10(x.sql_scale)))
	}
	return i
}

// TODO eliminate floating point arithmetic
fn (x XSQLVar) parse_long(raw_value []u8) Value {
	i := parse_i32(raw_value)
	if x.sql_scale != 0 {
		return i32(i * i64(math.pow10(x.sql_scale)))
	}
	return i
}

// TODO eliminate floating point arithmetic
fn (x XSQLVar) parse_int64(raw_value []u8) Value {
	i := parse_i64(raw_value)
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
			return x.parse_date(raw_value)
		}
		sql_type_time {
			return x.parse_time(raw_value)
		}
		sql_type_timestamp {
			return x.parse_timestamp(raw_value)
		}
		sql_type_time_tz {
			// return x.parse_time_tz(raw_value)
			return error('TODO')
		}
		sql_type_timestamp_tz {
			// return x.parse_timestamp_tz(raw_value)
			return error('TODO')
		}
		sql_type_float {
			return parse_f32(raw_value)
		}
		sql_type_double {
			return parse_f64(raw_value)
		}
		sql_type_boolean {
			return raw_value[0] != 0
		}
		sql_type_blob {
			return raw_value
		}
		else {
			return error(format_error_message('Unsupported data type ${x.sql_type}: ${low_priority_todo}'))
		}
	}
}

fn get_sql_scale(sql_scale u8) u8 {
	if sql_scale > 0 {
		return sql_scale
	}
	return sql_scale + 256
}

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/remote/client/BlrFromMessage.cpp
fn build_blr(xsqlda []XSQLVar) ![]u8 {
	len := xsqlda.len
	min_len := xsqlda.len * 3 + 8
	mut blr := strings.new_builder(min_len)
	// header: 4 bytes
	blr.write_byte(blr_version5)
	blr.write_byte(blr_begin)
	blr.write_byte(blr_message)
	blr.write_byte(0)
	// length: 2 bytes
	blr.write_byte(u8(len & 255))
	blr.write_byte(u8(len >> 8))

	for i := 0; i < len; i++ {
		v := xsqlda[i]
		sql_scale := get_sql_scale(v.sql_scale)
		match v.sql_type {
			sql_type_varying {
				blr.write_byte(blr_varying)
				blr.write_byte(u8(v.sql_len & 255))
				blr.write_byte(u8(v.sql_len >> 8))
			}
			sql_type_text {
				blr.write_byte(blr_text)
				blr.write_byte(u8(v.sql_len & 255))
				blr.write_byte(u8(v.sql_len >> 8))
			}
			sql_type_long {
				blr.write_byte(blr_long)
				blr.write_byte(u8(sql_scale))
			}
			sql_type_short {
				blr.write_byte(blr_short)
				blr.write_byte(u8(sql_scale))
			}
			sql_type_int64 {
				blr.write_byte(blr_int64)
				blr.write_byte(sql_scale)
			}
			sql_type_int128 {
				blr.write_byte(blr_int128)
				blr.write_byte(sql_scale)
			}
			sql_type_quad {
				blr.write_byte(blr_quad)
				blr.write_byte(sql_scale)
			}
			sql_type_double {
				blr.write_byte(blr_double)
			}
			sql_type_float {
				blr.write_byte(blr_float)
			}
			sql_type_d_float {
				blr.write_byte(blr_d_float)
			}
			sql_type_date {
				blr.write_byte(blr_sql_date)
			}
			sql_type_time {
				blr.write_byte(blr_sql_time)
			}
			sql_type_timestamp {
				blr.write_byte(blr_timestamp)
			}
			sql_type_blob {
				blr.write_byte(blr_blob2)
				blr.write_byte(0)
			}
			sql_type_array {
				blr.write_byte(blr_quad)
				blr.write_byte(0)
			}
			sql_type_boolean {
				blr.write_byte(blr_bool)
			}
			sql_type_dec64 {
				blr.write_byte(blr_dec64)
			}
			sql_type_dec128 {
				blr.write_byte(blr_dec128)
			}
			sql_type_time_tz {
				blr.write_byte(blr_sql_time_tz)
			}
			sql_type_timestamp_tz {
				blr.write_byte(blr_timestamp_tz)
			}
			else {
				return error(format_error_message('Unsupported data type ${v.sql_type}: ${low_priority_todo}'))
			}
		}
		blr.write_byte(blr_short)
		blr.write_byte(0)
	}
	blr.write_byte(blr_end)
	blr.write_byte(blr_eoc)
	return blr
}
