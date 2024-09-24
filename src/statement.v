module firebird

import context

pub struct Statement {
	query     string
	handle    i32
	blr       []u8 // https://www.firebirdfaq.org/faq187/
	stmt_type i32  // isc_info_sql_stmt_type
mut:
	conn Connection
}

// Close the statement.
// The statement will not be closed if it is in use by any query.
pub fn (mut stmt Statement) close() ! {
	return error('TODO')
}

// Execute a query that may return a result.
pub fn (mut stmt Statement) exec(ctx context.Context) !Result {
	return error('TODO')
}

// Execute a query with parameters that may return a result.
pub fn (mut stmt Statement) exec_params(ctx context.Context, parameters []Value) !Result {
	return error('TODO')
}

// Execute a query that may return rows.
pub fn (mut stmt Statement) query(ctx context.Context, parameters []Value) !Rows {
	return error('TODO')
}

// Execute a query with parameters that may return rows.
pub fn (mut stmt Statement) query_params(ctx context.Context, parameters []Value) !Rows {
	return error('TODO')
}
