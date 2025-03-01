module firebird

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/src/main/org/firebirdsql/gds/impl/wire/WireProtocolConstants.java
const op_connect = 1
const op_exit = 2
const op_accept = 3
const op_reject = 4
const op_protocrol = 5
const op_disconnect = 6
const op_response = 9
const op_attach = 19
const op_create = 20
const op_detach = 21
const op_transaction = 29
const op_commit = 30
const op_rollback = 31
const op_open_blob = 35
const op_get_segment = 36
const op_put_segment = 37
const op_close_blob = 39
const op_info_database = 40
const op_info_transaction = 42
const op_batch_segments = 44
const op_que_events = 48
const op_cancel_events = 49
const op_commit_retaining = 50
const op_event = 52
const op_connect_request = 53
const op_aux_connect = 53
const op_create_blob2 = 57
const op_allocate_statement = 62
const op_execute = 63
const op_execute_immediate = 64
const op_fetch = 65
const op_fetch_response = 66
const op_free_statement = 67
const op_prepare_statement = 68
const op_info_sql = 70
const op_dummy = 71
const op_execute2 = 76
const op_sql_response = 78
const op_drop_database = 81
const op_service_attach = 82
const op_service_detach = 83
const op_service_info = 84
const op_service_start = 85
const op_rollback_retaining = 86
const op_update_account_info = 87
const op_authenticate_user = 88
const op_partial = 89
const op_trusted_auth = 90
const op_cancel = 91
const op_cont_auth = 92
const op_ping = 93
const op_accept_data = 94
const op_abort_aux_connection = 95
const op_crypt = 96
const op_crypt_key_callback = 97
const op_cond_accept = 98

const cnct_user = 1
const cnct_passwd = 2
const cnct_host = 4
const cnct_group = 5
const cnct_user_verification = 6
const cnct_specific_data = 7
const cnct_plugin_name = 8
const cnct_login = 9
const cnct_plugin_list = 10
const cnct_client_crypt = 11

const connect_version_3 = 3

const arch_type_generic = 1

// https://github.com/FirebirdSQL/jaybird/blob/694801baab9083b7df83fe457ef71e8c89740d88/src/main/org/firebirdsql/gds/impl/wire/WireProtocolConstants.java#L168
const fb_protocol_flag = i32(0b0000_0000_0000_0000_1000_0000_0000_0000)

pub const isolation_level_read_commited_legacy = 0 // not supported
pub const isolation_level_read_commited = 1 // default
pub const isolation_level_repeatable_read = 2
pub const isolation_level_serializable = 3
pub const isolation_level_read_commited_ro = 4 // read only
