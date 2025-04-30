module firebird

pub struct Null {}

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

pub struct Column {
pub:
	field_name     string
	sql_type       string
	null_indicator bool
}

fn new_column(x XSQLVar) Column {
	return Column{
		field_name:     x.field_name
		sql_type:       xsqlvar_type_name[x.sql_type]
		null_indicator: x.null_indicator
	}
}

fn new_columns(xsqlda XSQLDA) []Column {
	mut res := []Column{len: xsqlda.vars.len}
	for i := 0; i < xsqlda.vars.len; i++ {
		x := xsqlda.vars[i]
		res[i] = new_column(x)
	}
	return res
}

pub struct Row {
pub:
	values []Value
}

fn new_row(row_data []Value) Row {
	return Row{
		values: row_data
	}
}

fn new_rows(data [][]Value) []Row {
	mut res := []Row{len: data.len}
	for i := 0; i < data.len; i++ {
		row_data := data[i]
		res[i] = new_row(row_data)
	}
	return res
}

// Result contains all rows
pub struct Result {
pub:
	// rows affected?
	columns []Column
	rows    []Row
mut:
	stmt &Statement
}

fn new_result(stmt &Statement, xsqlda XSQLDA, rows_data [][]Value) Result {
	if rows_data.len == 0 {
		return Result{
			stmt: stmt
		}
	}

	columns := new_columns(xsqlda)
	rows := new_rows(rows_data)
	return Result{
		columns: columns
		rows:    rows
		stmt:    stmt
	}
}

fn new_basic_result(stmt &Statement) Result {
	return new_result(stmt, XSQLDA{}, [][]Value{})
}
