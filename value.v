module firebird

// Value could be:
// - firebird.Null
// - firebird.DateTime
// - i32
// - i64
// - f32
// - f64
// - bool
// - []u8
// - string
pub interface Value {}

fn bad_type_message(t string) string {
	return 'Value is neither ${t} nor Null'
}

// Returns a DateTime from a Value, together with true if Value is Null.
// Returns an error if the Value is not a DateTime.
pub fn (value Value) get_date_time() !(DateTime, bool) {
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
pub fn (value Value) get_i32() !(i32, bool) {
	match value {
		i32 {
			return value, false
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
pub fn (value Value) get_i64() !(i64, bool) {
	match value {
		i64 {
			return value, false
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
pub fn (value Value) get_f32() !(f32, bool) {
	match value {
		f32 {
			return value, false
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
pub fn (value Value) get_f64() !(f64, bool) {
	match value {
		f64 {
			return value, false
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
pub fn (value Value) get_bool() !(bool, bool) {
	match value {
		bool {
			return value, false
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
pub fn (value Value) get_array_u8() !([]u8, bool) {
	match value {
		[]u8 {
			return value, false
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
pub fn (value Value) get_string() !(string, bool) {
	match value {
		string {
			return value, false
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
pub fn (value Value) get_date_time_or_zero() !DateTime {
	v, _ := value.get_date_time()!
	return v
}

// Returns i32 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a i32.
pub fn (value Value) get_i32_or_zero() !i32 {
	v, _ := value.get_i32()!
	return v
}

// Returns i64 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a i64.
pub fn (value Value) get_i64_or_zero() !i64 {
	v, _ := value.get_i64()!
	return v
}

// Returns f32 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a f32.
pub fn (value Value) get_f32_or_zero() !f32 {
	v, _ := value.get_f32()!
	return v
}

// Returns f64 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a f64.
pub fn (value Value) get_f64_or_zero() !f64 {
	v, _ := value.get_f64()!
	return v
}

// Returns bool from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a bool.
pub fn (value Value) get_bool_or_zero() !bool {
	v, _ := value.get_bool()!
	return v
}

// Returns []u8 from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a []u8.
pub fn (value Value) get_array_u8_or_zero() ![]u8 {
	v, _ := value.get_array_u8()!
	return v
}

// Returns string from a Value. If the Value is Null, it returns the default zero value.
// Returns an error if the Value is not a string.
pub fn (value Value) get_string_or_zero() !string {
	v, _ := value.get_string()!
	return v
}

// pub fn (value Value) date_time() ?DateTime {
// 	v, n := value.get_date_time()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) i32() ?i32 {
// 	v, n := value.get_i32()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) i64() ?i64 {
// 	v, n := value.get_i64()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) f32() ?f32 {
// 	v, n := value.get_f32()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) f64() ?f64 {
// 	v, n := value.get_f64()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) bool() ?bool {
// 	v, n := value.get_bool()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) array_u8() ?[]u8 {
// 	v, n := value.get_array_u8()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

// pub fn (value Value) string() ?string {
// 	v, n := value.get_string()! // need to handle error too.
// 	if n {
// 		return none
// 	}
// 	return v
// }

pub struct NullDateTime {
pub:
	value   DateTime
	is_null bool
}

pub fn (value Value) get_null_date_time() !NullDateTime {
	v, is_null := value.get_date_time()!
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

pub fn (value Value) get_null_i32() !NullI32 {
	v, is_null := value.get_i32()!
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

pub fn (value Value) get_null_i64() !NullI64 {
	v, is_null := value.get_i64()!
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

pub fn (value Value) get_null_f32() !NullF32 {
	v, is_null := value.get_f32()!
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

pub fn (value Value) get_null_f64() !NullF64 {
	v, is_null := value.get_f64()!
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

pub fn (value Value) get_null_bool() !NullBool {
	v, is_null := value.get_bool()!
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

pub fn (value Value) get_null_array_u8() !NullArrayU8 {
	v, is_null := value.get_array_u8()!
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

pub fn (value Value) get_null_string() !NullString {
	v, is_null := value.get_string()!
	return NullString{
		value:   v
		is_null: is_null
	}
}
