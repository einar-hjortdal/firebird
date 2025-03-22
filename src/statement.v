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

// Executes the statement with the given args
pub fn (mut stmt Statement) exec(ctx context.Context, args []Value) ![]Row {
	return error('TODO')
}
