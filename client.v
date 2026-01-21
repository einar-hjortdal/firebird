module firebird

import sync

// WIP

pub struct ClientConfig {
pub:
	// connection options?
	pool_size i32
}

// Client manages a pool of Connection
pub struct Client {
mut:
	connections      []&Connection
	idle_connections []&Connection
	pool_size        i32
	mutex            &sync.Mutex
}

pub fn new_client(c ClientConfig) !&Client {
	return &Client{
		pool_size: c.pool_size
		mutex:     sync.new_mutex()
	}
}

// Wraps Transaction
pub struct ClientTransaction {
mut:
	client &Client
	tx     &Transaction
}

// start_transaction returns a ClientTransaction
pub fn (mut c Client) start_transaction(isolation_level int, is_autocommit bool) !&ClientTransaction {
	// get connection
	tx := new_transaction(conn, isolation_level, is_autocommit)!
	return &ClientTransaction{
		client: c
		tx:     tx
	}
}

pub fn (mut ct ClientTransaction) prepare(query string) !&Statement {
	return ct.tx.prepare(query)!
}

// rollback wraps Transaction.rollback. Internally frees the connection.
pub fn (mut ct ClientTransaction) rollback() ! {
	ct.tx.rollback()!
	// return ct.tx.conn to ct.c
}

// commit wraps Transaction.commit. Internally frees the connection.
pub fn (mut ct ClientTransaction) commit() ! {
	ct.tx.commit()!
	// return ct.tx.conn to ct.c
}
