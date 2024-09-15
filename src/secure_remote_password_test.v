module firebird

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
