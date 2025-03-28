module firebird

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/jaybird-native/src/main/java/org/firebirdsql/jna/fbclient/XSQLVAR.java#L11
struct XSQLVAR {
	sql_type    int
	sql_scale   int
	sql_subtype int
	sql_len     int
	null_ok     bool
	field_name  string
	rel_name    string
	own_name    string
	alias_name  string
}
