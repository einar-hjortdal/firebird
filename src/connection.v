module firebird

import math.big
import context

@[heap]
struct Connection {
mut:
	p                    WireProtocol
	dsn                  DataSourceName
	column_name_to_lower bool
	is_autocommit        bool
	client_public_key    big.Integer
	client_secret_key    big.Integer
	transactions         []&Transaction
}

fn new_connection(dsn DataSourceName) !Connection {
	mut p := new_wire_protocol(dsn.address, dsn.options['timezone'])!
	column_name_to_lower := parse_bool(dsn.options['column_name_to_lower'])
	client_public_key, client_secret_key := get_client_seed()
	// p.connect(dsn.database, dsn.user, dsn.password, dsn.options, client_public_key)!
	// p.parse_connect_response
	// p.attach
	p.db_handle, _, _ = p.generic_response()!
	mut conn := Connection{
		p:                    p
		dsn:                  dsn
		column_name_to_lower: column_name_to_lower
		is_autocommit:        true
		client_public_key:    client_public_key
		client_secret_key:    client_secret_key
	}
	return conn
}

pub fn open(s string) !Connection {
	dsn := parse_dsn(s)!
	return new_connection(dsn)
}

// Begin a Transaction.
pub fn (mut conn Connection) begin_transaction(ctx context.Context, o TransactionOptions) !Transaction {
	return error('TODO')
}

// Close the connection.
// Calls Transaction.rollback on any running transaction.
pub fn (mut conn Connection) close() ! {
	len := conn.transactions.len
	for i := 0; i < len; i++ {
		conn.transactions[i].rollback()!
	}

	conn.p.detach()!
	conn.p.generic_response()!
	conn.p.conn.close()!
	return
}

// Execute query that may return a result.
pub fn (mut conn Connection) exec(ctx context.Context, query string) !Result {
	return error('TODO')
}

// Execute query with params that may return a result.
pub fn (mut conn Connection) exec_params(ctx context.Context, query string, parameters []Value) !Result {
	return error('TODO')
}

// Execute query that may return rows.
pub fn (mut conn Connection) query(ctx context.Context, query string) !Rows {
	return error('TODO')
}

// Execute query with params that may return rows.
pub fn (mut conn Connection) query_params(ctx context.Context, query string, parameters []Value) !Rows {
	return error('TODO')
}

// Prepare a statement
pub fn (mut conn Connection) prepare(ctx context.Context, query string) !Statement {
	return error('TODO')
}
