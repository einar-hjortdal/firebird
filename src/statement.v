module firebird

import context

pub struct Statement {
	query     string
	blr       []u8 // https://www.firebirdfaq.org/faq187/
	stmt_type i32  // isc_info_sql_stmt_type
mut:
	conn        Connection
	stmt_handle i32
}

fn new_statement(mut c Connection, query string) !Statement {
	mut stmt := Statement{
		query: query
		conn:  c
	}
	stmt.conn.p.allocate_statement()!
	if stmt.conn.p.accept_type == ptype_lazy_send {
		stmt.conn.p.lazy_response_count++
		stmt.stmt_handle = -1
	} else {
		stmt.stmt_handle, _, _ = stmt.conn.p.generic_response()!
	}

	stmt.conn.p.prepare_statement(stmt.stmt_handle, stmt.conn.transactions[0].tx_handle,
		query)!
	return error('TODO') // Understand better how each connection owns a transaction, and how to create non-recursive structures.
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
