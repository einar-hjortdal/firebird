module firebird

pub struct Null {}

// Value could be:
// - firebird.Null
// - firebird.Time
// - i32
// - i64
// - f32
// - f64
// - bool
// - []u8
// - string
pub interface Value {}

pub struct Column {
	name           string
	data_type_name string
	may_be_null    bool
}

pub fn (c Column) name() string {
	return c.name
}

pub fn (c Column) data_type_name() string {
	return c.data_type_name
}

pub fn (c Column) may_be_null() bool {
	return c.may_be_null
}

pub struct Row {
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

pub fn (r Row) values() []Value {
	return r.values
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

fn new_result(stmt &Statement, data [][]Value) Result {
	if data.len == 0 {
		return Result{
			stmt: stmt
		}
	}

	rows := new_rows(data)
	return Result{
		rows: rows
		stmt: stmt
	}
}

fn new_basic_result(stmt &Statement) Result {
	return new_result(stmt, [][]Value{})
}

pub fn (r Result) columns() []Column {
	return r.columns
}

pub fn (r Result) rows() []Row {
	return r.rows
}
