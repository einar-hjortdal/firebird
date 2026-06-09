module firebird

import sync
import time

pub const default_max_pool_size = 10
pub const default_min_pool_size = 2

const no_idle_message = 'no idle connection available'
const no_idle = NoIdle{}

struct NoIdle {}

fn (e NoIdle) msg() string {
	return no_idle_message
}

fn (e NoIdle) code() int {
	return 0
}

pub struct ClientConfig {
pub:
	url           string // required, see new_connection
	max_pool_size ?i32
	min_pool_size ?i32
	// TODO:
	// max_idle_time time.Duration
	// max_life_time time.Duration
}

struct ChannelMessage {}

struct ClientConnection {
	created_at time.Time
mut:
	idle_since time.Time // should be an atomic but V atomics are experimental, use mutex instead
	fbconn     &Connection
	mutex      &sync.Mutex
}

fn (mut cc ClientConnection) set_idle_since() {
	cc.mutex.lock()
	cc.idle_since = time.now()
	cc.mutex.unlock()
}

// Client manages a pool of Connection
// TODO add atomic to ensure a closed pool stays closed
pub struct Client {
	url           string
	max_pool_size i32
	min_pool_size i32
	queue         chan ChannelMessage
mut:
	connections             []&ClientConnection // active connections
	idle_connections        []&ClientConnection // available connections
	connections_length      i32                 // number of connections in the pool
	idle_connections_length i32                 // number of available connections in the pool
	mutex                   &sync.Mutex
}

fn (mut c Client) wait_turn() ! {
	select {
		c.queue <- ChannelMessage{} {
			return
		}
		// else {} // fall through to timer
	}

	// TODO sync.pool timer timeout
}

fn (mut c Client) free_turn() {
	_ := <-c.queue
}

fn (mut c Client) add_idle_connection() ! {
	connection := &ClientConnection{
		created_at: time.now()
		idle_since: time.now()
		fbconn:     new_connection(c.url)!
		mutex:      sync.new_mutex()
	}
	c.mutex.lock()
	c.connections << connection
	c.idle_connections << connection
	c.mutex.unlock()
}

fn (mut c Client) add_idle_connection_and_free_turn() ! {
	c.add_idle_connection() or {
		c.mutex.lock()
		c.connections_length--
		c.idle_connections_length--
		c.mutex.unlock()
	}
	c.free_turn()
}

fn (mut c Client) check_min_idle_connections() {
	if c.min_pool_size == 0 { return }

	for c.connections_length < c.max_pool_size && c.idle_connections_length < c.min_pool_size {
		select {
			c.queue <- ChannelMessage{} {
				c.connections_length++
				c.idle_connections_length++
				go c.add_idle_connection_and_free_turn()
			}
			else {
				return
			}
		}
	}
}

fn pool_size_or_default(o ?i32, default i32) !i32 {
	v := o or { return default }
	if v < 0 { return error(format_error_message('pool size cannot be smaller than 0')) }
	return v
}

// Client manages a pool of connections to the Firebird server.
// By default it keeps default_min_pool_size active connections to the server and, when needed, adds more up to ClientConfig.max_pool_size, which is default_max_pool_size by default. Then, new database operations will wait for an existing operation to finish.
pub fn new_client(c ClientConfig) !&Client {
	max_pool_size := pool_size_or_default(c.max_pool_size, default_max_pool_size)!
	if max_pool_size < default_min_pool_size {
		return error(format_error_message('max pool size cannot be smaller than ${default_min_pool_size}'))
	}

	min_pool_size := pool_size_or_default(c.min_pool_size, default_min_pool_size)!

	mut client := &Client{
		url:              c.url
		max_pool_size:    max_pool_size
		min_pool_size:    min_pool_size
		queue:            chan ChannelMessage{cap: max_pool_size}
		connections:      []&ClientConnection{cap: max_pool_size}
		idle_connections: []&ClientConnection{cap: max_pool_size}
		mutex:            sync.new_mutex()
	}

	client.mutex.lock()
	client.check_min_idle_connections()
	client.mutex.unlock()
	return client
}

fn (mut c Client) new_client_connection() !&ClientConnection {
	connection := &ClientConnection{
		created_at: time.now()
		fbconn:     new_connection(c.url)!
		mutex:      sync.new_mutex()
	}
	c.mutex.lock()
	c.connections << connection
	c.connections_length++
	c.mutex.unlock()
	return connection
}

fn (mut c Client) pop_idle() !&ClientConnection {
	len := c.idle_connections.len
	if len == 0 {
		return no_idle
	}

	i := len - 1
	conn := c.idle_connections[i]
	c.idle_connections = c.idle_connections[..i] // TODO is this in-place? does it need to be?
	c.idle_connections_length--
	c.check_min_idle_connections()
	return conn
}

fn (mut c Client) get() !&ClientConnection {
	c.wait_turn()!
	for {
		c.mutex.lock()
		conn := c.pop_idle() or {
			c.mutex.unlock()
			match err {
				NoIdle {
					break
				}
				else {
					c.free_turn()
					return err
				}
			}
		}
		c.mutex.unlock()
		// TODO connection health check. close connection if bad, continue loop to find a healthy one
		return conn
	}

	conn := c.new_client_connection() or {
		c.free_turn()
		return err
	}
	return conn
}

fn (mut c Client) put(mut client_connection ClientConnection) {
	c.mutex.lock()
	// TODO check health: if needed close connection and remove from pool instead
	client_connection.set_idle_since()
	c.idle_connections << client_connection
	c.idle_connections_length++
	c.mutex.unlock()
	c.free_turn()
}

// removes an active connection. TODO remove idle too?
fn (mut c Client) remove(mut client_connection ClientConnection) {
	c.mutex.lock()
	for i := 0; i < c.connections.len; i++ {
		conn := c.connections[i]
		if conn == client_connection {
			c.connections[i] = c.connections[c.connections.len - 1] // https://github.com/vlang/v/issues/27400
			c.connections.delete(c.connections.len - 1)
			c.connections_length--
			c.check_min_idle_connections()
			break
		}
	}
	c.mutex.unlock()
}

fn (mut c Client) close(mut client_connection ClientConnection) ! {
	client_connection.fbconn.close()!
}

pub struct ClientTransaction {
mut:
	client            &Client
	client_connection &ClientConnection
	tx                &Transaction
}

pub fn (mut c Client) start_transaction(isolation_level int, is_autocommit bool) !&ClientTransaction {
	mut client_connection := c.get()!
	tx := new_transaction(mut client_connection.fbconn, isolation_level, is_autocommit) or {
		c.put(mut client_connection)
		return err
	}

	return &ClientTransaction{
		client:            c
		client_connection: client_connection
		tx:                tx
	}
}

pub fn (mut ct ClientTransaction) execute(query string, params ...Value) !Result {
	return ct.tx.execute(query, ...params)
}

pub fn (mut ct ClientTransaction) prepare(query string) !&Statement {
	return ct.tx.prepare(query)!
}

// rollback wraps Transaction.rollback. Internally frees the connection.
pub fn (mut ct ClientTransaction) rollback() ! {
	ct.tx.rollback()!
	ct.client.put(mut ct.client_connection)
}

// commit wraps Transaction.commit. Internally frees the connection.
pub fn (mut ct ClientTransaction) commit() ! {
	ct.tx.commit()!
	ct.client.put(mut ct.client_connection)
}

