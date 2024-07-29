module firebird

import arrays
import os
import math.big

const plugin_list = 'Srp256,Srp,Legacy_Auth'
const buffer_len = 1024
const max_char_length = 32767
const blob_segment_size = 32000

fn user_identification(user string, auth_plugin_name string, wire_crypt bool, client_public big.Integer) []u8 {
	get_system_user := fn () []u8 {
		system_user := os.getenv('USER')
		if system_user == '' {
			return os.getenv('USERNAME').bytes()
		}
		return system_user.bytes()
	}

	get_hostname := fn () []u8 {
		hostname := os.hostname() or { '' }
		return hostname.bytes()
	}

	get_wire_crypt_u8 := fn [wire_crypt] () u8 {
		if wire_crypt == true {
			return u8(1)
		}
		return u8(0)
	}

	get_srp_client_public := fn [client_public] () []u8 {
		b, _ := client_public.bytes()
		len := b.len
		if len > 254 {
			mut res := [u8(cnct_specific_data), 255, 0]
			res = arrays.append(res, b[..254])
			res = arrays.append(res, [u8(cnct_specific_data), u8((len - 254) + 1), 1])
			res = arrays.append(res, b[254..])
			return res
		}

		return arrays.append([u8(cnct_specific_data), u8(len + 1), 0], b)
	}

	get_specific_data := fn [auth_plugin_name, get_srp_client_public] () []u8 {
		if auth_plugin_name == 'Srp' || auth_plugin_name == 'Srp256' {
			return get_srp_client_public()
		}

		if auth_plugin_name == 'Legacy_Auth' {
			panic('Unsupported plugin: ${auth_plugin_name}')
		}
		panic('Unknown plugin name: ${auth_plugin_name}')
	}

	user_name_bytes := user.to_upper().bytes()
	user_name := arrays.append([u8(cnct_login), u8(user_name_bytes.len)], user_name_bytes)

	plugin_name_bytes := auth_plugin_name.bytes()
	plugin_name := arrays.append([u8(cnct_plugin_name), u8(plugin_name_bytes.len)], plugin_name_bytes)

	plugins_bytes := firebird.plugin_list.bytes()
	plugins := arrays.append([u8(cnct_plugin_list), u8(plugins_bytes.len)], plugins_bytes)

	specific_data := get_specific_data()

	wire_crypt_byte := get_wire_crypt_u8()
	wire_crypt_bytes := [u8(cnct_client_crypt), 4, wire_crypt_byte, 0, 0, 0]

	system_user_bytes := get_system_user()
	system_user := arrays.append([u8(cnct_user), u8(system_user_bytes.len)], system_user_bytes)

	hostname_bytes := get_hostname()
	hostname := arrays.append([u8(cnct_host), u8(hostname_bytes.len)], hostname_bytes)

	verification := [u8(cnct_user_verification), 0]

	mut res := arrays.append(user_name, plugin_name)
	res = arrays.append(res, plugins)
	res = arrays.append(res, specific_data)
	res = arrays.append(res, wire_crypt_bytes)
	res = arrays.append(res, system_user)
	res = arrays.append(res, hostname)
	res = arrays.append(res, verification)
	return res
}
