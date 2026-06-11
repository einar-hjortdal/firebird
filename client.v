module firebird

import sync
import time

pub const default_max_pool_size = 10
pub const default_min_pool_size = 2
pub const default_max_idle_time = time.hour * 1
pub const default_max_life_time = 0

struct NoIdle {}

fn (e NoIdle) msg() string {
	return 'no idle connection available'
}

fn (e NoIdle) code() int {
	return 0
}

struct ClientClosed {}

fn (e ClientClosed) msg() string {
	return 'client was closed'
}

fn (e ClientClosed) code() int {
	return 0
}

pub struct ClientConfig {
pub:
	url                string
	max_pool_size      ?i32
	min_pool_size      ?i32
	conn_max_idle_time ?time.Duration
	conn_max_life_time ?time.Duration
}

struct ChannelMessage {}

struct ClientConnection {
	created_at time.Time
mut:
	idle_since time.Time
	fbconn     &Connection
	mutex      &sync.Mutex
}

fn (mut cc ClientConnection) set_idle_since() {
	cc.mutex.lock()
	cc.idle_since = time.now()
	cc.mutex.unlock()
}

fn (mut cc ClientConnection) close() {
	cc.mutex.lock()
	cc.fbconn.close() or {}
	cc.mutex.unlock()
}

// Client manages a pool of Connection
pub struct Client {
	url                string
	max_pool_size      i32
	min_pool_size      i32
	queue              chan ChannelMessage
	conn_max_idle_time time.Duration
	conn_max_life_time time.Duration
mut:
	connections      []&ClientConnection // active connections
	idle_connections []&ClientConnection // available connections
	is_closed        bool
	mutex            &sync.Mutex
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

fn (mut c Client) add_idle_connection_and_free_turn() {
	c.add_idle_connection() or {}
	c.free_turn()
}

fn (mut c Client) check_min_connections() {
	mut n_conns := c.connections.len
	for n_conns < c.min_pool_size {
		select {
			c.queue <- ChannelMessage{} {
				n_conns++
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
	if v < 0 { return new_error('pool size cannot be smaller than 0') }
	return v
}

fn life_time_or_default(d ?time.Duration, default time.Duration) !time.Duration {
	lt := d or { return default }
	if lt < 0 { return new_error('life_time cannot be smaller than 0') }
	return lt
}

// Client manages a pool of connections to the Firebird server.
// By default it keeps default_min_pool_size active connections to the server and, when needed, adds more up to ClientConfig.max_pool_size, which is default_max_pool_size by default. Then, new database operations will wait for an existing operation to finish.
pub fn new_client(c ClientConfig) !&Client {
	max_pool_size := pool_size_or_default(c.max_pool_size, default_max_pool_size)!
	if max_pool_size < default_min_pool_size {
		return new_error('max pool size cannot be smaller than ${default_min_pool_size}')
	}

	mut client := &Client{
		url:                c.url
		max_pool_size:      max_pool_size
		min_pool_size:      pool_size_or_default(c.min_pool_size, default_min_pool_size)!
		queue:              chan ChannelMessage{cap: max_pool_size}
		connections:        []&ClientConnection{cap: max_pool_size}
		idle_connections:   []&ClientConnection{cap: max_pool_size}
		conn_max_idle_time: life_time_or_default(c.conn_max_idle_time, default_max_idle_time)!
		conn_max_life_time: life_time_or_default(c.conn_max_life_time, default_max_life_time)!
		mutex:              sync.new_mutex()
	}

	client.mutex.lock()
	client.check_min_connections()
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
	c.mutex.unlock()
	return connection
}

fn (mut c Client) pop_idle() !&ClientConnection {
	len := c.idle_connections.len
	if len == 0 {
		return NoIdle{}
	}

	last_i := len - 1
	conn := c.idle_connections[last_i]
	c.idle_connections.delete(last_i)
	return conn
}

fn (mut c Client) get() !&ClientConnection {
	if c.is_closed {
		return ClientClosed{}
	}

	c.wait_turn()!
	for {
		c.mutex.lock()
		mut conn := c.pop_idle() or {
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
		if c.is_healthy_connection(mut conn) {
			return conn
		}

		c.close_connection(mut conn)
		continue
	}

	conn := c.new_client_connection() or {
		c.free_turn()
		return err
	}
	return conn
}

fn (mut c Client) put(mut client_connection ClientConnection) {
	c.mutex.lock()
	client_connection.set_idle_since()
	c.idle_connections << client_connection
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
			break
		}
	}
	c.mutex.unlock()
}

fn (mut c Client) close_connection(mut client_connection ClientConnection) {
	c.remove(mut client_connection)
	client_connection.close()
}

fn (mut c Client) connection_is_too_old(mut client_connection ClientConnection, now time.Time) bool {
	return c.conn_max_life_time > 0 && now - client_connection.created_at > c.conn_max_life_time
}

fn (mut c Client) connection_waited_too_long(mut client_connection ClientConnection, now time.Time) bool {
	return c.conn_max_idle_time > 0 && now - client_connection.idle_since > c.conn_max_idle_time
}

fn (mut c Client) is_healthy_connection(mut client_connection ClientConnection) bool {
	now := time.now()
	if c.connection_is_too_old(mut client_connection, now) {
		return false
	}

	if c.connection_waited_too_long(mut client_connection, now) {
		return false
	}

	client_connection.fbconn.health_check() or { return false }

	return true
}

pub fn (mut c Client) close() {
	c.mutex.lock()
	for i := 0; i < c.connections.len; i++ {
		c.connections[i].close()
	}
	c.connections.clear()
	c.idle_connections.clear()
	c.is_closed = true
	c.mutex.unlock()
}

pub struct ClientTransaction {
mut:
	client            &Client
	client_connection &ClientConnection
	transaction       &Transaction
}

pub fn (mut c Client) start_transaction(isolation_level int) !&ClientTransaction {
	mut client_connection := c.get()!
	transaction := client_connection.fbconn.start_transaction(isolation_level) or {
		c.put(mut client_connection)
		return err
	}

	return &ClientTransaction{
		client:            c
		client_connection: client_connection
		transaction:       transaction
	}
}

pub fn (mut ct ClientTransaction) execute(query string, params ...Value) !Result {
	return ct.transaction.execute(query, ...params)
}

pub fn (mut ct ClientTransaction) prepare(query string) !&Statement {
	return ct.transaction.prepare(query)!
}

// Internally frees the connection.
pub fn (mut ct ClientTransaction) rollback() ! {
	defer {
		ct.client.put(mut ct.client_connection)
	}
	ct.transaction.rollback()!
}

// Internally frees the connection.
pub fn (mut ct ClientTransaction) commit() ! {
	defer {
		ct.client.put(mut ct.client_connection)
	}
	ct.transaction.commit()!
}
