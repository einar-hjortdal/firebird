module firebird

fn bad_type_message(t string) string {
	return 'Value is neither ${t} nor Null'
}

// Returns a DateTime from a Value, together with true if Value is Null.
// Returns an error if the Value is not a DateTime.
pub fn get_date_time(value Value) !(DateTime, bool) {
	match value {
		DateTime {
			return *value, false
		}
		Null {
			return DateTime{}, true
		}
		else {
			return error(format_error_message(bad_type_message('DateTime')))
		}
	}
}

// Returns a i32 from a Value, together with true if Value is Null.
// Returns an error if the Value is not a i32.
pub fn get_i32(value Value) !(i32, bool) {
	match value {
		i32 {
			return *value, false
		}
		Null {
			return 0, true
		}
		else {
			return error(format_error_message(bad_type_message('i32')))
		}
	}
}

// Returns a i64 from a Value, together with true if Value is Null.
// Returns an error if the Value is not a i64.
pub fn get_i64(value Value) !(i64, bool) {
	match value {
		i64 {
			return *value, false
		}
		Null {
			return 0, true
		}
		else {
			return error(format_error_message(bad_type_message('i64')))
		}
	}
}

// Returns a f32 from a Value, together with true if Value is Null.
// Returns an error if the Value is not a f32.
pub fn get_f32(value Value) !(f32, bool) {
	match value {
		f32 {
			return *value, false
		}
		Null {
			return 0, true
		}
		else {
			return error(format_error_message(bad_type_message('f32')))
		}
	}
}

// Returns a f64 from a Value, together with true if Value is Null.
// Returns an error if the Value is not a f64.
pub fn get_f64(value Value) !(f64, bool) {
	match value {
		f64 {
			return *value, false
		}
		Null {
			return 0, true
		}
		else {
			return error(format_error_message(bad_type_message('f64')))
		}
	}
}

// Returns a bool from a Value, together with true if Value is Null.
// Returns an error if the Value is not a bool.
pub fn get_bool(value Value) !(bool, bool) {
	match value {
		bool {
			return *value, false
		}
		Null {
			return false, true
		}
		else {
			return error(format_error_message(bad_type_message('bool')))
		}
	}
}

// Returns a []u8 from a Value, together with true if Value is Null.
// Returns an error if the Value is not a []u8.
pub fn get_array_u8(value Value) !([]u8, bool) {
	match value {
		[]u8 {
			return *value, false
		}
		Null {
			return []u8{}, true
		}
		else {
			return error(format_error_message(bad_type_message('[]u8')))
		}
	}
}

// Returns a string from a Value, together with true if Value is Null.
// Returns an error if the Value is not a string.
pub fn get_string(value Value) !(string, bool) {
	match value {
		string {
			return *value, false
		}
		Null {
			return '', true
		}
		else {
			return error(format_error_message(bad_type_message('string')))
		}
	}
}

// Returns DateTime from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a DateTime.
pub fn get_date_time_or_zero(value Value) !DateTime {
	v, _ := get_date_time(value)!
	return v
}

// Returns i32 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a i32.
pub fn get_i32_or_zero(value Value) !i32 {
	v, _ := get_i32(value)!
	return v
}

// Returns i64 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a i64.
pub fn get_i64_or_zero(value Value) !i64 {
	v, _ := get_i64(value)!
	return v
}

// Returns f32 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a f32.
pub fn get_f32_or_zero(value Value) !f32 {
	v, _ := get_f32(value)!
	return v
}

// Returns f64 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a f64.
pub fn get_f64_or_zero(value Value) !f64 {
	v, _ := get_f64(value)!
	return v
}

// Returns bool from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a bool.
pub fn get_bool_or_zero(value Value) !bool {
	v, _ := get_bool(value)!
	return v
}

// Returns []u8 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a []u8.
pub fn get_array_u8_or_zero(value Value) ![]u8 {
	v, _ := get_array_u8(value)!
	return v
}

// Returns string from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a string.
pub fn get_string_or_zero(value Value) !string {
	v, _ := get_string(value)!
	return v
}

pub struct NullDateTime {
pub:
	value   DateTime
	is_null bool
}

pub fn get_null_date_time(value Value) !NullDateTime {
	v, is_null := get_date_time(value)!
	return NullDateTime{
		value:   v
		is_null: is_null
	}
}

pub struct NullI32 {
pub:
	value   i32
	is_null bool
}

pub fn get_null_i32(value Value) !NullI32 {
	v, is_null := get_i32(value)!
	return NullI32{
		value:   v
		is_null: is_null
	}
}

pub struct NullI64 {
pub:
	value   i64
	is_null bool
}

pub fn get_null_i64(value Value) !NullI64 {
	v, is_null := get_i64(value)!
	return NullI64{
		value:   v
		is_null: is_null
	}
}

pub struct NullF32 {
pub:
	value   f32
	is_null bool
}

pub fn get_null_f32(value Value) !NullF32 {
	v, is_null := get_f32(value)!
	return NullF32{
		value:   v
		is_null: is_null
	}
}

pub struct NullF64 {
pub:
	value   f64
	is_null bool
}

pub fn get_null_f64(value Value) !NullF64 {
	v, is_null := get_f64(value)!
	return NullF64{
		value:   v
		is_null: is_null
	}
}

pub struct NullBool {
pub:
	value   bool
	is_null bool
}

pub fn get_null_bool(value Value) !NullBool {
	v, is_null := get_bool(value)!
	return NullBool{
		value:   v
		is_null: is_null
	}
}

pub struct NullArrayU8 {
pub:
	value   []u8
	is_null bool
}

pub fn get_null_array_u8(value Value) !NullArrayU8 {
	v, is_null := get_array_u8(value)!
	return NullArrayU8{
		value:   v
		is_null: is_null
	}
}

pub struct NullString {
pub:
	value   string
	is_null bool
}

pub fn get_null_string(value Value) !NullString {
	v, is_null := get_string(value)!
	return NullString{
		value:   v
		is_null: is_null
	}
}
