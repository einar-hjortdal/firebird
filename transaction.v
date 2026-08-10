module firebird

pub interface Transaction {
mut:
	commit() !
	rollback() !
	execute(query string, params ...Value) !Result
	prepare(query string) !&Statement
}

@[heap]
pub struct ConnectionTransaction {
	isolation_level int
mut:
	conn          &Connection
	is_autocommit bool
	tx_handle     i32
}

fn (mut tx ConnectionTransaction) set() ! {
	tpb := get_tpb(tx.isolation_level)
	tx.conn.p.transaction(tpb)!
	tx_handle, _, _ := tx.conn.p.generic_response()!
	tx.tx_handle = tx_handle
}

fn new_transaction(mut conn Connection, isolation_level int, is_autocommit bool) !&ConnectionTransaction {
	mut tx := &ConnectionTransaction{
		conn:            conn
		isolation_level: isolation_level
		is_autocommit:   is_autocommit
	}
	tx.set()!
	return tx
}

pub fn (mut tx ConnectionTransaction) commit() ! {
	tx.conn.p.commit(tx.tx_handle)!
	_, _, _ := tx.conn.p.generic_response()!
}

pub fn (mut t ConnectionTransaction) rollback() ! {
	t.conn.p.rollback(t.tx_handle)!
	_, _, _ := t.conn.p.generic_response()!
}

pub fn (mut tx ConnectionTransaction) prepare(query string) !&Statement {
	return new_statement(mut tx, query)!
}

// execute prepares a statement with the given query, executes it with the given parameters and returns
// the result.
pub fn (mut tx ConnectionTransaction) execute(query string, params ...Value) !Result {
	mut stmt := tx.prepare(query)!
	result := stmt.execute(...params)!
	stmt.close()!
	return result
}
