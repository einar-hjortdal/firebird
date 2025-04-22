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
