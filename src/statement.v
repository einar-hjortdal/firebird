module firebird

pub struct Statement {
	query       string
	blr         []u8 // https://www.firebirdfaq.org/faq187/
	stmt_handle i32
	stmt_type   i32 // isc_info_sql_stmt_type
mut:
	tx Transaction
}

fn new_statement(mut tx Transaction, query string) !Statement {
	tx.conn.p.allocate_statement()!
	mut stmt_handle := i32(0)
	if tx.conn.p.accept_type == ptype_lazy_send {
		tx.conn.p.lazy_response_count++
		stmt_handle = -1
	} else {
		stmt_handle, _, _ = tx.conn.p.generic_response()!
	}

	tx.conn.p.prepare_statement(stmt_handle, tx.tx_handle, query)!
	if tx.conn.p.accept_type == ptype_lazy_send && tx.conn.p.lazy_response_count > 0 {
		tx.conn.p.lazy_response_count--
		stmt_handle, _, _ = tx.conn.p.generic_response()!
	}

	_, _, buf := tx.conn.p.generic_response()!
	// TODO definitely need to parse xsql data :(
	// stmt_type, xsqlda := tx.conn.p.parse_xsqlda(buf, stmt_handle)!
	// blr = calculate_blr(xsqlda)
	return Statement{
		query:       query
		tx:          tx
		stmt_handle: stmt_handle
		// stmt_type: stmt_type
		// blr:         blr
	}
}

// Close the statement.
// The statement will not be closed if it is in use by any query.
pub fn (mut stmt Statement) close() ! {
	return error('TODO')
}

// Executes the statement with the given args
pub fn (mut stmt Statement) exec(args []Value) ![]Row {
	stmt.tx.conn.p.execute(stmt.stmt_handle, stmt.tx.tx_handle, args)!
	stmt.tx.conn.p.generic_response()!
	return new_row(stmt)
}
