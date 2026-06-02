module firebird

import strings

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/include/firebird/impl/blr.h#L45
const blr_text = 14
const blr_text2 = 15
const blr_short = 7
const blr_long = 8
const blr_quad = 9
const blr_float = 10
const blr_double = 27
const blr_d_float = 11
const blr_timestamp = 35
const blr_varying = 37
const blr_varying2 = 38
const blr_blob = 261
const blr_cstring = 40
const blr_cstring2 = 41
const blr_blob_id = 45
const blr_sql_date = 12
const blr_sql_time = 13
const blr_int64 = 16
const blr_blob2 = 17
const blr_domain_name = 18
const blr_domain_name2 = 19
const blr_not_nullable = 20
const blr_column_name = 21
const blr_column_name2 = 22
const blr_bool = 23
const blr_dec64 = 24
const blr_dec128 = 25
const blr_int128 = 26
const blr_sql_time_tz = 28
const blr_timestamp_tz = 29
const blr_ex_time_tz = 30
const blr_ex_timestamp_tz = 31

const blr_version5 = 5
const blr_begin = 2
const blr_message = 4
const blr_end = 255
const blr_eoc = 76

// https://github.com/FirebirdSQL/firebird/blob/v5.0-release/src/remote/client/BlrFromMessage.cpp
fn build_blr(xsqlda XSQLDA) ![]u8 {
	len := xsqlda.vars.len * 2
	min_len := xsqlda.vars.len * 3 + 8
	mut blr := strings.new_builder(min_len)
	// header: 4 bytes
	blr.write_u8(blr_version5)
	blr.write_u8(blr_begin)
	blr.write_u8(blr_message)
	blr.write_u8(0)
	// length: 2 bytes
	blr.write_u8(u8(len & 255))
	blr.write_u8(u8(len >> 8))

	for i := 0; i < xsqlda.vars.len; i++ {
		v := xsqlda.vars[i]
		match v.sql_type {
			sql_type_varying {
				blr.write_u8(blr_varying) // TODO switch to blr_varying2
				blr.write_u8(u8(v.sql_len & 255))
				blr.write_u8(u8(v.sql_len >> 8))
			}
			sql_type_text {
				blr.write_u8(blr_text) // TODO blr_text2
				blr.write_u8(u8(v.sql_len & 255))
				blr.write_u8(u8(v.sql_len >> 8))
			}
			sql_type_dec64 {
				blr.write_u8(blr_dec64)
			}
			sql_type_dec128 {
				blr.write_u8(blr_dec128)
			}
			sql_type_int128 {
				blr.write_u8(blr_int128)
				blr.write_u8(u8(v.sql_scale))
			}
			sql_type_double {
				blr.write_u8(blr_double)
			}
			sql_type_float {
				blr.write_u8(blr_float)
			}
			sql_type_d_float {
				blr.write_u8(blr_d_float)
			}
			sql_type_date {
				blr.write_u8(blr_sql_date)
			}
			sql_type_time {
				blr.write_u8(blr_sql_time)
			}
			sql_type_time_tz {
				blr.write_u8(blr_sql_time_tz)
			}
			sql_type_time_tz_ex {
				blr.write_u8(blr_ex_time_tz)
			}
			sql_type_timestamp {
				blr.write_u8(blr_timestamp)
			}
			sql_type_timestamp_tz {
				blr.write_u8(blr_timestamp_tz)
			}
			sql_type_timestamp_tz_ex {
				blr.write_u8(blr_ex_timestamp_tz)
			}
			sql_type_blob {
				blr.write_u8(blr_quad) // blr_blob2 causes errors, why?
				blr.write_u8(0)
			}
			sql_type_array {
				blr.write_u8(blr_quad)
				blr.write_u8(0)
			}
			sql_type_long {
				blr.write_u8(blr_long)
				blr.write_u8(u8(v.sql_scale))
			}
			sql_type_short {
				blr.write_u8(blr_short)
				blr.write_u8(u8(v.sql_scale))
			}
			sql_type_int64 {
				blr.write_u8(blr_int64)
				blr.write_u8(u8(v.sql_scale))
			}
			sql_type_quad {
				blr.write_u8(blr_quad)
				blr.write_u8(u8(v.sql_scale))
			}
			sql_type_boolean {
				blr.write_u8(blr_bool)
			}
			sql_type_null {
				blr.write_u8(blr_text)
				blr.write_u8(u8(v.sql_len & 255))
				blr.write_u8(u8(v.sql_len >> 8))
			}
			else {
				return error(format_error_message('Unsupported data type ${v.sql_type}: ${low_priority_todo}'))
			}
		}
		blr.write_u8(blr_short)
		blr.write_u8(0)
	}
	blr.write_u8(blr_end)
	blr.write_u8(blr_eoc)
	return blr
}
