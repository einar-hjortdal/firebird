module firebird

import net.urllib

struct DataSourceName {
mut:
	address  string
	database string
	user     string
	password string
	options  map[string]string
}

const default_options = {
	'auth_plugin_name':     'Srp256'
	'charset':              'UTF8'
	'column_name_to_lower': 'false'
	'role':                 ''
	'timezone':             ''
	'wire_crypt':           'true'
}

// https://firebirdsql.org/file/documentation/html/en/firebirddocs/qsg5/firebird-5-quickstartguide.html#qsg5-databases-connstrings-tcpip
// Despite the information in the quickstart guide, connectors in other languages enforce the `firebird://`
// protocol portion of the url. This connector does the same, but it can be changed with a pull request.
fn parse_url(s string) !urllib.URL {
	p := 'firebird://'
	if s.starts_with(p) {
		return urllib.parse(s)!
	}
	return urllib.parse('${p}${s}')!
}

fn get_address(s string) string {
	if s.contains(':') {
		return s
	}
	return '${s}:3050'
}

fn get_options_from_raw_query(rq string) !map[string]string {
	query_values := urllib.parse_query(rq)!
	m := query_values.to_map()
	mut res := map[string]string{}
	for k, v in default_options {
		if k in m {
			res[k] = m[k][0]
		} else {
			res[k] = v
		}
	}
	return res
}

fn parse_dsn(s string) !DataSourceName {
	u := parse_url(s)!
	options := get_options_from_raw_query(u.raw_query)!

	return DataSourceName{
		address:  get_address(u.host)
		database: u.path
		user:     u.user.username
		password: u.user.password
		options:  options
	}
}
