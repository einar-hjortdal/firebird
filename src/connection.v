module firebird

import math.big

@[heap]
struct Connection {
	dsn                  DataSourceName
	client_public_key    big.Integer
	client_secret_key    big.Integer
	column_name_to_lower bool
	is_autocommit        bool
mut:
	p &WireProtocol
}

// `s` is the dsn in the format [firebird://]<user>:<password>@<host><database>
// the `timezone` option is supported but it only accepts named zones, not offsets.
// see connection_text.v for an example.
pub fn new_connection(s string) !&Connection {
	dsn := parse_dsn(s)!
	mut p := new_wire_protocol(dsn.address, dsn.options['timezone'])!
	client_public_key, client_secret_key := get_client_seed()
	p.connect(dsn.database, dsn.user, dsn.options, client_public_key)!
	p.parse_connect_response(dsn.user, dsn.password, dsn.options, client_public_key, client_secret_key)!
	p.attach(dsn.database, dsn.user, dsn.password, dsn.options['role'])!
	p.db_handle, _, _ = p.generic_response()!
	return &Connection{
		p:                    p
		dsn:                  dsn
		column_name_to_lower: parse_bool(dsn.options['column_name_to_lower'])
		is_autocommit:        true
		client_public_key:    client_public_key
		client_secret_key:    client_secret_key
	}
}

// Close the connection.
pub fn (mut c Connection) close() ! {
	c.p.detach()!
	c.p.generic_response()!
	c.p.disconnect()!
	c.p.conn.close()!
}

// Almost all operations in Firebird occur in the context of a transaction. Units of work are isolated
// between a start point and end point. Changes to data remain reversible until the moment the client
// application instructs the server to commit them.
pub fn (mut c Connection) start_transaction(isolation_level int) !&Transaction {
	if isolation_level in [isolation_level_read_commited_ro, isolation_level_read_commited,
		isolation_level_repeatable_read, isolation_level_serializable] {
		return new_transaction(mut c, isolation_level, false)!
	}

	return error(format_error_message('Isolation level not supported.'))
}
