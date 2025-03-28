module firebird

pub struct Null {}

// Value could be:
// - Null
// - i32
// - i64
// - f32
// - f64
// - bool
// - []u8
// - string
// - time.Time
pub interface Value {}

pub struct Row {
	values []Value
}

pub fn (r Row) values() []Value {
	return r.values
}

// Result contains all rows of a query
pub struct Result {
	columns []string
	rows    []Row
mut:
	stmt Statement
}

pub fn new_result(stmt Statement) Result {
	return Result{
		stmt: stmt
	}
}

pub fn (r Result) columns() []string {
	return r.columns
}

pub fn (r Result) rows() []Row {
	return r.rows
}
