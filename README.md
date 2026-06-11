<span style="background-color: #226f54; font-size: 125%; padding-top: 1.25%; padding-right: 2.5%; padding-bottom: 1.25%; padding-left: 2.5%; border-radius: 25px;">This project is active: new features are being developed, bugs are being fixed.</span>

# firebird

A pure V FirebirdSQL connector and toolkit. See [TODO.md](TODO.md) for a list of features.

## Example usage

```V
import einar_hjortdal.firebird

url := 'firebird://fbusr:fbpwd@localhost:3050/var/lib/firebird/data/firebird.fdb'
// establish a connection to the firebird server
mut conn := firebird.new_connection(url)!

// start a transaction
mut tx := conn.start_transaction(firebird.isolation_level_read_commited)!

// get the result of the query
result := tx.execute('SELECT code FROM foo WHERE id = ?', 2)!

// close the transaction and the connection when no longer needed
tx.rollback()!
conn.close()!

// the result contains rows
rows := result.rows()
if rows.len == 0 {
  return error('code not found with id 2')
}

// each row has selected values
values := rows[0].values()

// the selected value is varchar, and it can be null
// we have utilities to handle these values, see value.v for more
code := values[0].get_null_string()!
if code.is_null() {
  return error('code missing for id 2')
}
return code.value()

// Use a client that manages a pool of connections for you
// This client will keep some connections open, open new connections as needed, and close bad connections.
client := firebird.new_client(firebird.ClientConfig{ url: url })!
```

## Development

Contributions are very welcome.

- [Issues](https://github.com/einar-hjortdal/firebird/issues)
- [TODO.md](./TODO.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)

All you have to do to contribute to this project is to start a Firebird container like so:

```bash
sudo docker run \
  --rm \
  --detach \
  --name=firebird-server \
  --env=FIREBIRD_ROOT_PASSWORD=rootpwd \
  --env=FIREBIRD_USER=fbusr \
  --env=FIREBIRD_PASSWORD=fbpwd \
  --env=FIREBIRD_DATABASE=firebird.fdb \
  --env=FIREBIRD_DATABASE_DEFAULT_CHARSET=UTF8 \
  --volume=firebird-data:/var/lib/firebird/data \
  --publish=3050:3050 \
  firebirdsql/firebird
```
