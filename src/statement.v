module firebird

pub struct Statement {
	query       string
	blr         []u8 // https://www.firebirdfaq.org/faq187/
	stmt_type   i32  // isc_info_sql_stmt_type
	stmt_handle i32
mut:
	tx        Transaction
	is_closed bool
}

fn parse_statement_type(buf []u8) !(i32, int) {
	for i := 0; i < buf.len; i++ {
		if buf[i] == u8(isc_info_sql_stmt_type) && buf[i + 1] == 4 && buf[i + 2] == 0 {
			i++
			len := parse_little_endian_i16(buf[i..i + 2])
			i += 2
			stmt_type := parse_little_endian_i32(buf[i..i + len])
			next_index := i + len
			return stmt_type, next_index
		}
	}
	return error(format_error_message('could not parse statement type, missing from buffer'))
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
	stmt_type, xsqlda := tx.conn.p.parse_xsqlda(buf, stmt_handle)!
	blr := build_blr(xsqlda)!
	return Statement{
		query:       query
		tx:          tx
		stmt_handle: stmt_handle
		stmt_type:   stmt_type
		blr:         blr
	}
}

// Close the statement.
// The statement will not be closed if it is in use by any query.
pub fn (mut stmt Statement) close() ! {
	if stmt.is_closed == true {
		return
	}

	stmt.tx.conn.p.free_statement(stmt.stmt_handle, dsql_drop)!
	stmt.is_closed = true

	if stmt.tx.conn.p.accept_type == ptype_lazy_send {
		stmt.tx.conn.p.lazy_response_count++
	} else {
		stmt.tx.conn.p.generic_response()!
	}
}

// Executes the statement with the given args.
pub fn (mut stmt Statement) exec(args []Value) !Result {
	if stmt.is_closed {
		return error(format_error_message('failed to execute statement: stmt.is_closed is `true`'))
	}

	if stmt.stmt_type == isc_info_sql_stmt_exec_procedure {
		// TODO
	}
	stmt.tx.conn.p.execute(stmt.stmt_handle, stmt.tx.tx_handle, args)!
	stmt.tx.conn.p.generic_response()!
	return new_result(stmt)
}
