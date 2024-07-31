module firebird

import arrays
import crypto.sha1
import math.big
import encoding.hex

const srp_key_size = 128
const srp_salt_size = 32

const big_prime_bytes = hex.decode('E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7') or {
	panic(err) // should never panic
}
const big_integer_string = '1277432915985975349439481660349303019122249720001'
const big_integer_max = '340282366920938463463374607431768211456'

fn get_prime() (big.Integer, big.Integer, big.Integer) {
	prime := big.integer_from_bytes(firebird.big_prime_bytes)
	g := big.integer_from_i64(2)
	k := big.integer_from_string(firebird.big_integer_string) or {
		panic(err) // should never panic
	}
	return prime, g, k
}

fn pad(v big.Integer) []u8 {
	mut buf := []u8{}
	mut n := big.integer_from_i64(0) + v

	for i := 0; i < firebird.srp_key_size; i++ {
		buf = arrays.concat(buf, u8(big.integer_from_i64(255).bitwise_and(n).int()))
		n = n / big.integer_from_i64(256)
	}

	// swap u8 positions
	for i := 0; i < firebird.srp_key_size; i++ {
		j := firebird.srp_key_size - 1 - i
		i_value := buf[i]
		j_value := buf[j]
		buf[i] = j_value
		buf[j] = i_value
	}

	get_first_non_zero_index := fn [buf] () int {
		len := buf.len
		for i := 0; i < len; i++ {
			if buf[i] != 0 {
				return i
			}
		}
		return len - 1
	}

	first_non_zero_index := get_first_non_zero_index()
	return buf[first_non_zero_index..]
}

fn get_scramble(key_a big.Integer, key_b big.Integer) big.Integer {
	// key_a:A client public ephemeral values
	// key_b:B server public ephemeral values
	mut digest := sha1.new()
	digest.write(pad(key_a)) or { panic(err) }
	digest.write(pad(key_b)) or { panic(err) }
	return big.integer_from_bytes(digest.sum([]u8{}))
}

//  fn get_client_seed() (big.Integer, big.Integer) {
//  	prime, g, _ := get_prime()
//  	// a should be a random number in the range [0, 340282366920938463463374607431768211456)
//  	public :=
//  	secret := g.big_mod_pow(public, prime) or { panic(err) }
//  	return public, secret
//  }
