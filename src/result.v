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

fn new_row() !Row {
	return error('TODO')
}

pub fn (r Row) values() []Value {
	return r.values
}

// Result contains all rows
pub struct Result {
	status  string // TODO
	columns []Column
	rows    []Row
mut:
	stmt Statement
}

pub fn new_result(stmt Statement) Result {
	// get all rows
	// for ? {
	// row_data, is_there_more := stmt.tx.conn.p.fetch_response(stmt.stmt_handle, stmt.tx.tx_handle, stmt.xsqlda)
	//  }
	// for ? {
	//	new_row()
	// }
	return Result{
		stmt: stmt
	}
}

pub fn (r Result) status() string {
	return r.status
}

pub fn (r Result) columns() []Column {
	return r.columns
}

pub fn (r Result) rows() []Row {
	return r.rows
}
