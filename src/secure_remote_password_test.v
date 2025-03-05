module firebird

import crypto.rand
import math.big

fn get_verifier(user string, password string, salt []u8) big.Integer {
	prime, g, _ := get_prime()
	x := get_user_hash(salt, user, password)
	verifier := g.big_mod_pow(x, prime) or { panic(err) }
	return verifier
}

fn get_server_session(user string, password string, salt []u8, client_public_key big.Integer, server_public_key big.Integer, server_secret_key big.Integer) []u8 {
	prime, _, _ := get_prime()
	u := get_scramble(client_public_key, server_public_key)
	v := get_verifier(user, password, salt)
	vu := v.big_mod_pow(u, prime) or { panic(err) }
	avu := (client_public_key * vu) % prime
	session_secret := avu.big_mod_pow(server_secret_key, prime) or { panic(err) }
	return big_int_to_sha1(session_secret)
}

fn get_server_seed(v big.Integer) (big.Integer, big.Integer) {
	prime, g, k := get_prime()
	server_secret_key := rand.int_big(big_integer_max) or { panic(err) }
	gb := g.big_mod_pow(server_secret_key, prime) or { panic(err) } // gb = pow(g, b, N)
	kv := (k * v) % prime // kv = (k * v) % N
	server_public_key := (kv + gb) % prime // B = (kv + gb) % N
	return server_public_key, server_secret_key
}

fn get_salt() []u8 {
	return rand.read(srp_salt_size) or { panic(err) }
}

fn test_secure_remote_password() {
	user := 'SYSDBA'
	password := 'rootpwd'

	client_public_key, client_secret_key := get_client_seed()
	salt := get_salt()
	v := get_verifier(user, password, salt)
	server_public_key, server_secret_key := get_server_seed(v)
	server_key := get_server_session(user, password, salt, client_public_key, server_public_key,
		server_secret_key)
	_, client_key_one := get_client_proof(user, password, salt, client_public_key, server_public_key,
		client_secret_key, 'Srp')
	client_key_one_len := client_key_one.len
	for i := 0; i < client_key_one_len; i++ {
		assert client_key_one[i] == server_key[i]
	}

	_, client_key_two := get_client_proof(user, password, salt, client_public_key, server_public_key,
		client_secret_key, 'Srp256')
	client_key_two_len := client_key_two.len
	for i := 0; i < client_key_two_len; i++ {
		assert client_key_two[i] == server_key[i]
	}
}
