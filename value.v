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

pub interface Nullable[T] {
	value() T
	is_null() bool
}

pub fn (n Nullable[T]) none_value() ?T {
	if n.is_null() {
		return none
	}
	return n.value()
}

pub struct NullDateTime {
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

pub fn (p NullDateTime) value() DateTime {
	return p.value
}

pub fn (p NullDateTime) is_null() bool {
	return p.is_null
}

pub struct NullI32 {
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

pub fn (p NullI32) value() i32 {
	return p.value
}

pub fn (p NullI32) is_null() bool {
	return p.is_null
}

pub struct NullI64 {
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

pub fn (p NullI64) value() i64 {
	return p.value
}

pub fn (p NullI64) is_null() bool {
	return p.is_null
}

pub struct NullF32 {
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

pub fn (p NullF32) value() f32 {
	return p.value
}

pub fn (p NullF32) is_null() bool {
	return p.is_null
}

pub struct NullF64 {
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

pub fn (p NullF64) value() f64 {
	return p.value
}

pub fn (p NullF64) is_null() bool {
	return p.is_null
}

pub struct NullBool {
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

pub fn (p NullBool) value() bool {
	return p.value
}

pub fn (p NullBool) is_null() bool {
	return p.is_null
}

pub struct NullArrayU8 {
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

pub fn (p NullArrayU8) value() []u8 {
	return p.value
}

pub fn (p NullArrayU8) is_null() bool {
	return p.is_null
}

pub struct NullString {
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

pub fn (p NullString) value() string {
	return p.value
}

pub fn (p NullString) is_null() bool {
	return p.is_null
}
