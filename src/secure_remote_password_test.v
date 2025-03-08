module firebird

import crypto.rand
import encoding.hex
import math.big

const srp_salt_size = 32

// These values are obtained using Jaybird
fn test_get_client_proof() {
	user := 'FBUSR'
	password := 'fbpwd'
	plugin_name := 'Srp256'
	salt := hex.decode('41434331313038393841383533333930413434394436433832324642323941344135444339343031373532333533353331443030334235363244323036384333') or {
		panic(err)
	}
	client_public_key := big.integer_from_radix('b9c5052c23b826cd50390142b2bbb8a6b72809594d3e2ec9ef1de270f0fd654b4c1f6ef9354bd6a6905fad1f8ea2e1fc7d502a81da7d9bb6cf3ead2fe9e8de842ec9eab0aa008b4f50dbccc0538e8ce9f15e00c667f3f8f69e498c750f55f71f0b7ade139fa7406a95468b1257e8e54bc91248c11481196922cf84b5be74e055',
		16) or { panic(err) }
	server_public_key := big.integer_from_radix('6f460f8184112b6bd6e14d833e4eb881a17b25c6fb70bbe02db67528a4d4f213adf272af080574b44cda8d63ccc7f66482a73150156576e8f4998fe0dd9724d1182170f15aa6222f81e04a7abb05a1fee54209734f307f42468919565a082b12418c700db9cc1e50f88dd39cce32df0bded4f68c06ca8a851373fb432cd0fc9f',
		16) or { panic(err) }
	client_secret_key := big.integer_from_radix('676add8528d92dd956aab0332a197462', 16) or {
		panic(err)
	}
	expected_scramble := big.integer_from_radix('34239ef7c032bd74949aac7892d68dff22a84049',
		16) or { panic(err) }
	expected_user_hash := big.integer_from_radix('b5397eedf64eacec1be2fb66ffd7009f2381dd5a',
		16) or { panic(err) }
	expected_k := hex.decode('c6837f71b3a8f342921fe19ac0d08830ef86ab0a') or { panic(err) }
	expected_m := hex.decode('e3f01a2478148df58a5f124e5fff37b8c46c3277ff237df83e54baf6890a9899') or {
		panic(err)
	}

	// session_key
	session_key := get_session_key(user, password, salt, client_public_key, server_public_key,
		client_secret_key)
	assert expected_k == session_key

	// get_scramble
	scramble := get_scramble(client_public_key, server_public_key)
	assert scramble == expected_scramble

	// get_user_hash
	hash := get_user_hash(salt, user, password)
	assert hash == expected_user_hash

	// get_client_proof
	m, k := get_client_proof(user, password, salt, client_public_key, server_public_key,
		client_secret_key, plugin_name)
	assert k == expected_k
	assert m == expected_m
}

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
