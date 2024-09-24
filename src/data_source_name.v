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

fn normalize_dsn_protocol(s string) !urllib.URL {
	if !s.starts_with('firebird://') {
		return urllib.parse(s)!
	}
	return urllib.parse(s)!
}

fn parse_dsn(s string) !DataSourceName {
	u := normalize_dsn_protocol(s)!
	// if u.user is nil, then return error(format_error_message('Unknown user'))
	return DataSourceName{}
}
