module firebird

import crypto.rand
import crypto.sha1
import crypto.sha256
import hash
import math.big

// http://srp.stanford.edu/design.html

// https://github.com/FirebirdSQL/jaybird/blob/64d0249ce0f28693ab91d7294174d80d788caf66/src/main/org/firebirdsql/gds/ng/wire/auth/srp/SrpClient.java#L29
const srp_key_size = 128

// https://github.com/FirebirdSQL/jaybird/blob/64d0249ce0f28693ab91d7294174d80d788caf66/src/main/org/firebirdsql/gds/ng/wire/auth/srp/SrpClient.java#L114
const big_integer_max = big.integer_from_i64(2).pow(srp_key_size)

// https://github.com/FirebirdSQL/jaybird/blob/64d0249ce0f28693ab91d7294174d80d788caf66/src/main/org/firebirdsql/gds/ng/wire/auth/srp/SrpClient.java#L33
const big_prime_hex = 'E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7'

// https://github.com/FirebirdSQL/jaybird/blob/64d0249ce0f28693ab91d7294174d80d788caf66/src/main/org/firebirdsql/gds/ng/wire/auth/srp/SrpClient.java#L34
const generator_int = 2

// https://github.com/FirebirdSQL/jaybird/blob/64d0249ce0f28693ab91d7294174d80d788caf66/src/main/org/firebirdsql/gds/ng/wire/auth/srp/SrpClient.java#L35
const multiplier_string = '1277432915985975349439481660349303019122249719989'

fn get_prime() (big.Integer, big.Integer, big.Integer) {
	prime := big.integer_from_radix(big_prime_hex, 16) or { panic(err) } // it will never panic
	generator := big.integer_from_i64(generator_int)
	k := big.integer_from_string(multiplier_string) or { panic(err) } // it will never panic
	return prime, generator, k
}

fn get_first_non_zero_index(a []u8) int {
	len := a.len
	for i := 0; i < len; i++ {
		if a[i] != 0 {
			return i
		}
	}
	return len - 1
}

fn get_scramble(client_public_key big.Integer, server_public_key big.Integer) big.Integer {
	mut digest := sha1.new()
	digest.write(big_integer_to_bytes(client_public_key)) or { panic(err) }
	digest.write(big_integer_to_bytes(server_public_key)) or { panic(err) }
	return big.integer_from_bytes(digest.sum([]u8{}))
}

fn get_client_seed() (big.Integer, big.Integer) {
	prime, generator, _ := get_prime()
	client_secret_key := rand.int_big(big_integer_max) or { panic(err) } // will never panic
	client_public_key := generator.big_mod_pow(client_secret_key, prime) or { panic(err) } // will never panic
	return client_public_key, client_secret_key
}

fn get_string_hash(s string) big.Integer {
	mut digest := sha1.new()
	digest.write(s.bytes()) or { panic(err) }
	return big.integer_from_bytes(digest.sum([]u8{}))
}

fn get_user_hash(salt []u8, user string, password string) big.Integer {
	mut hash1 := sha1.new()
	hash1.write('${user}:${password}'.bytes()) or { panic(err) }
	mut hash2 := sha1.new()
	hash2.write(salt) or { panic(err) }
	hash2.write(hash1.sum([]u8{})) or { panic(err) }
	return big.integer_from_bytes(hash2.sum([]u8{}))
}

fn big_integer_to_bytes(b big.Integer) []u8 {
	bytes, _ := b.bytes()
	return bytes
}

fn big_int_to_sha1(n big.Integer) []u8 {
	mut digest := sha1.new()
	n_bytes := big_integer_to_bytes(n)
	digest.write(n_bytes) or { panic(err) } // TODO when does digest.write panic?
	return sha1.sum([]u8{})
}

// https://github.com/FirebirdSQL/jaybird/blob/64d0249ce0f28693ab91d7294174d80d788caf66/src/main/org/firebirdsql/gds/ng/wire/auth/srp/SrpClient.java#L163
fn get_session_key(user string, password string, salt []u8, client_public_key big.Integer, server_public_key big.Integer, client_secret_key big.Integer) []u8 {
	prime, generator, k := get_prime()
	u := get_scramble(client_public_key, server_public_key)
	x := get_user_hash(salt, user, password)
	gx := generator.big_mod_pow(x, prime) or { panic(err) } // gx = pow(g, x, N)
	kgx := (k * gx) % prime // kgx = (k * gx) % N
	diff := (server_public_key - kgx) % prime // diff = (B - kgx) % N
	ux := (u * x) % prime // ux = (u * x) % N
	aux := (client_secret_key + ux) % prime // aux = (a + ux) % N
	session_secret := diff.big_mod_pow(aux, prime) or { panic(err) } // (B - kg^x) ^ (a+ ux)
	return big_int_to_sha1(session_secret)
}

fn new_digest(plugin_name string) hash.Hash {
	if plugin_name == 'Srp' {
		return sha1.new()
	}
	if plugin_name == 'Srp256' {
		return sha256.new()
	}
	panic(format_error_message('Secure Remote Password error: unsupported plugin name'))
}

// get_client_proof gets the verification message from Secure Remote Password equation.
// M = H(H(N) xor H(g), H(I), s, A, B, K)
// M is the verification message
// H is the hash function
// s is the salt
// g is the generator
// A is the client public key
// B is the server public key
// K is the session key
fn get_client_proof(user string, password string, salt []u8, client_public_key big.Integer, server_public_key big.Integer, client_secret_key big.Integer, plugin_name string) ([]u8, []u8) {
	prime, generator, _ := get_prime()
	session_key := get_session_key(user, password, salt, client_public_key, server_public_key,
		client_secret_key)
	n1 := big.integer_from_bytes(big_int_to_sha1(prime))
	n2 := big.integer_from_bytes(big_int_to_sha1(generator))
	n3 := n1.big_mod_pow(n2, prime) or { panic(err) }
	n4 := get_string_hash(user)

	mut digest := new_digest(plugin_name)
	digest.write(big_integer_to_bytes(n3)) or { panic(err) }
	digest.write(big_integer_to_bytes(n4)) or { panic(err) }
	digest.write(salt) or { panic(err) }
	digest.write(big_integer_to_bytes(client_public_key)) or { panic(err) }
	digest.write(big_integer_to_bytes(server_public_key)) or { panic(err) }
	digest.write(session_key) or { panic(err) }
	m := digest.sum([]u8{})

	return m, session_key
}
