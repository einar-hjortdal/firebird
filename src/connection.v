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
	transactions         []Transaction
}

fn new_connection(dsn DataSourceName) !Connection {
	mut p := new_wire_protocol(dsn.address, dsn.options['timezone'])!
	client_public_key, client_secret_key := get_client_seed()
	p.connect(dsn.database, dsn.user, dsn.options, client_public_key)!
	p.parse_connect_response(dsn.user, dsn.password, dsn.options, client_public_key, client_secret_key)!
	p.attach(dsn.database, dsn.user, dsn.password, dsn.options['role'])!
	p.db_handle, _, _ = p.generic_response()!
	return Connection{
		p:                    p
		dsn:                  dsn
		column_name_to_lower: parse_bool(dsn.options['column_name_to_lower'])
		is_autocommit:        true
		client_public_key:    client_public_key
		client_secret_key:    client_secret_key
	}
}

pub fn open(s string) !Connection {
	dsn := parse_dsn(s)!
	return new_connection(dsn)
}

// Close the connection.
// Calls Transaction.rollback on any running transaction.
pub fn (mut c Connection) close() ! {
	len := c.transactions.len
	for i := 0; i < len; i++ {
		c.transactions[i].rollback()!
	}

	c.p.detach()!
	c.p.generic_response()!
	c.p.conn.close()!
}

// Execute a query
pub fn (mut c Connection) query(ctx context.Context, query string, args []Value) ![]Row {
	mut stmt := c.prepare(ctx, query)!
	result := stmt.exec(ctx, args)!
	stmt.close()!
	return result
}

// Prepares a statement
pub fn (mut c Connection) prepare(ctx context.Context, query string) !Statement {
	return new_statement(mut c, query)!
}

fn (mut conn Connection) private_begin(isolation_level int) !Transaction {
	t := new_transaction(mut conn, isolation_level, false, true)!
	return t
}

// Begins a Transaction
pub fn (mut c Connection) begin(ctx context.Context, isolation_level int) !Transaction {
	if isolation_level in [isolation_level_read_commited_ro, isolation_level_read_commited,
		isolation_level_repeatable_read, isolation_level_serializable] {
		return c.private_begin(isolation_level)
	}

	return error(format_error_message('Isolation level not supported.'))
}
