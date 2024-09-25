module firebird

import arrays

pub struct Transaction {
	isolation_level int
mut:
	conn          &Connection
	is_autocommit bool
	need_begin    bool
	handle        i32
}

const partial = [u8(isc_tpb_version3), u8(isc_tpb_write), u8(isc_tpb_wait)]

fn get_tpb(isolation_level int) []u8 {
	match isolation_level {
		isolation_level_read_commited_legacy {
			return arrays.concat(partial, u8(isc_tpb_read_committed), u8(isc_tpb_no_rec_version))
		}
		isolation_level_read_commited {
			return arrays.concat(partial, u8(isc_tpb_read_committed), u8(isc_tpb_rec_version))
		}
		isolation_level_repeatable_read {
			return arrays.concat(partial, u8(isc_tpb_concurrency))
		}
		isolation_level_serializable {
			return arrays.concat(partial, u8(isc_tpb_consistency))
		}
		isolation_level_read_commited_ro {
			return [
				u8(isc_tpb_version3),
				u8(isc_tpb_read),
				u8(isc_tpb_wait),
				u8(isc_tpb_read_committed),
				u8(isc_tpb_rec_version),
			]
		}
		else {
			return []u8{}
		}
	}
}

fn (mut t Transaction) begin() ! {
	tpb := get_tpb(t.isolation_level)
	t.conn.p.transaction(tpb)!
	handle, _, _ := t.conn.p.generic_response()!
	t.handle = handle
	t.need_begin = false
	t.conn.transactions = arrays.concat(t.conn.transactions, t)
	return
}

fn new_transaction(mut conn Connection, isolation_level int, is_autocommit bool, with_begin bool) !Transaction {
	mut t := Transaction{
		conn:            conn
		isolation_level: isolation_level
		is_autocommit:   is_autocommit
	}

	if with_begin {
		t.begin()!
	} else {
		t.need_begin = true
	}

	return t
}

pub fn (mut t Transaction) commit() ! {
	t.conn.p.commit(t.handle)!
	_, _, _ := t.conn.p.generic_response()!
	t.is_autocommit = t.conn.is_autocommit
	t.need_begin = true
	return
}

pub fn (mut t Transaction) rollback() ! {
	t.conn.p.rollback(t.handle)!
	_, _, _ := t.conn.p.generic_response()!
	t.is_autocommit = t.conn.is_autocommit
	t.need_begin = true
	return
}

pub fn (mut t Transaction) exec(ctx context.Context, query string) !Result {
	return error('TODO')
}

pub fn (mut t Transaction) exec_params(ctx context.Context, query string, parameters []Value) !Result {
	return error('TODO')
}

pub fn (mut t Transaction) query(ctx context.Context, query string) !Rows {
	return error('TODO')
}

pub fn (mut t Transaction) query_params(ctx context.Context, query string, parameters []Value) !Rows {
	return error('TODO')
}

pub fn (mut t Transaction) prepare(ctx context.Context, query string) !Statement {
	return error('TODO')
}
