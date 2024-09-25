module firebird

import context
import sync

// TODO
struct ClientOptions {}

// This is the struct that users create and interface with.
// It maintains a pool of connections.
// Similar to https://github.com/einar-hjortdal/redict/blob/pending/src/pool/pool.v
struct Client {
	options ClientOptions
	queue   chan int
mut:
	active    []&Connection
	idle      []&Connection // currently available
	pool_size int           // currently open
	mutex     sync.Mutex
}

// creates a new Client
pub fn new_client() !Client {
	return error('TODO')
}

// closes all open connections.
pub fn (mut c Client) close() ! {
	return error('TODO')
}

// retrieves a connection from the pool.
pub fn (mut c Client) get_connection() !Connection {
	return error('TODO')
}

// returns a connection to the pool.
pub fn (mut c Client) put_connection(mut conn Connection) ! {
	return error('TODO')
}

// Execute query that may return a result.
pub fn (mut c Client) exec(ctx context.Context, query string) !Result {
	return error('TODO')
}

// Execute query with params that may return a result.
pub fn (mut c Client) exec_params(ctx context.Context, query string, parameters []Value) !Result {
	return error('TODO')
}

// Execute query that may return rows.
pub fn (mut c Client) query(ctx context.Context, query string) !Rows {
	return error('TODO')
}

// Execute query with params that may return rows.
pub fn (mut c Client) query_params(ctx context.Context, query string, parameters []Value) !Rows {
	return error('TODO')
}

// Prepare a statement
pub fn (mut c Client) prepare(ctx context.Context, query string) !Statement {
	return error('TODO')
}
