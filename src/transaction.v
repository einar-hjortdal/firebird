module firebird

pub struct Transaction {
	isolation_level int
mut:
	conn          Connection
	is_autocommit bool
	tx_handle     i32
}

fn (mut t Transaction) set() ! {
	tpb := get_tpb(t.isolation_level)
	t.conn.p.transaction(tpb)!
	tx_handle, _, _ := t.conn.p.generic_response()!
	t.tx_handle = tx_handle
}

fn new_transaction(mut conn Connection, isolation_level int, is_autocommit bool) !Transaction {
	mut t := Transaction{
		conn:            conn
		isolation_level: isolation_level
		is_autocommit:   is_autocommit
	}
	t.set()!
	return t
}

pub fn (mut t Transaction) commit() ! {
	t.conn.p.commit(t.tx_handle)!
	_, _, _ := t.conn.p.generic_response()!
	t.is_autocommit = t.conn.is_autocommit
}

pub fn (mut t Transaction) rollback() ! {
	t.conn.p.rollback(t.tx_handle)!
	_, _, _ := t.conn.p.generic_response()!
	t.is_autocommit = t.conn.is_autocommit
}

pub fn (mut t Transaction) prepare_statement(query string) !Statement {
	return error('TODO')
}
