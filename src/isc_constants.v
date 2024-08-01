module firebird

// https://github.com/FirebirdSQL/jaybird/blob/27c3d39325e0d1b011b43fa45a9daf9dcd0a9c85/src/main/org/firebirdsql/gds/ISCConstants.java
const isc_info_end = 1
const isc_info_truncated = 2
const isc_info_error = 3
const isc_info_data_not_ready = 4
const isc_info_length = 126
const isc_info_flag_end = 127

const isc_info_db_id = 4
const isc_info_reads = 5
const isc_info_writes = 6
const isc_info_fetches = 7
const isc_info_marks = 8
const isc_info_implementation = 11
const isc_info_version = 12
const isc_info_base_level = 13
const isc_info_page_size = 14
const isc_info_num_buffers = 15
const isc_info_limbo = 16
const isc_info_current_memory = 17
const isc_info_max_memory = 18
const isc_info_window_turns = 19
const isc_info_license = 20
const isc_info_allocation = 21
const isc_info_attachment_id = 22
const isc_info_read_seq_count = 23
const isc_info_read_idx_count = 24
const isc_info_insert_count = 25
const isc_info_update_count = 26
const isc_info_delete_count = 27
const isc_info_backout_count = 28
const isc_info_purge_count = 29
const isc_info_expunge_count = 30
const isc_info_sweep_interval = 31
const isc_info_ods_version = 32
const isc_info_ods_minor_version = 33
const isc_info_no_reserve = 34
const isc_info_logfile = 35
const isc_info_cur_logfile_name = 36
const isc_info_cur_log_part_offset = 37
const isc_info_num_wal_buffers = 38
const isc_info_wal_buffer_size = 39
const isc_info_wal_ckpt_length = 40
const isc_info_wal_cur_ckpt_interval = 41
const isc_info_wal_prv_ckpt_fname = 42
const isc_info_wal_prv_ckpt_poffset = 43
const isc_info_wal_recv_ckpt_fname = 44
const isc_info_wal_recv_ckpt_poffset = 45
const isc_info_wal_grpc_wait_usecs = 47
const isc_info_wal_num_io = 48
const isc_info_wal_avg_io_size = 49
const isc_info_wal_num_commits = 50
const isc_info_wal_avg_grpc_size = 51
const isc_info_forced_writes = 52
const isc_info_user_names = 53
const isc_info_page_errors = 54
const isc_info_record_errors = 55
const isc_info_bpage_errors = 56
const isc_info_dpage_errors = 57
const isc_info_ipage_errors = 58
const isc_info_ppage_errors = 59
const isc_info_tpage_errors = 60
const isc_info_set_page_buffers = 61
const isc_info_db_sql_dialect = 62
const isc_info_db_read_only = 63
const isc_info_db_size_in_pages = 64
const isc_info_att_charset = 101
const isc_info_db_class = 102
const isc_info_firebird_version = 103
const isc_info_oldest_transaction = 104
const isc_info_oldest_active = 105
const isc_info_oldest_snapshot = 106
const isc_info_next_transaction = 107
const isc_info_db_provider = 108
const isc_info_active_transactions = 109
const isc_info_active_tran_count = 110
const isc_info_creation_date = 111
const isc_info_db_file_size = 112

// isc_info_sql_records items
const isc_info_req_select_count = 13
const isc_info_req_insert_count = 14
const isc_info_req_update_count = 15
const isc_info_req_delete_count = 16

const isc_info_svc_svr_db_info = 50
const isc_info_svc_get_license = 51
const isc_info_svc_get_license_mask = 52
const isc_info_svc_get_config = 53
const isc_info_svc_version = 54
const isc_info_svc_server_version = 55
const isc_info_svc_implementation = 56
const isc_info_svc_capabilities = 57
const isc_info_svc_user_dbpath = 58
const isc_info_svc_get_env = 59
const isc_info_svc_get_env_lock = 60
const isc_info_svc_get_env_msg = 61
const isc_info_svc_line = 62
const isc_info_svc_to_eof = 63
const isc_info_svc_timeout = 64
const isc_info_svc_get_licensed_users = 65
const isc_info_svc_limbo_trans = 66
const isc_info_svc_running = 67
const isc_info_svc_get_users = 68

const isc_tpb_version1 = 1
const isc_tpb_version3 = 3
const isc_tpb_consistency = 1
const isc_tpb_concurrency = 2
const isc_tpb_shared = 3
const isc_tpb_protected = 4
const isc_tpb_exclusive = 5
const isc_tpb_wait = 6
const isc_tpb_nowait = 7
const isc_tpb_read = 8
const isc_tpb_write = 9
const isc_tpb_lock_read = 10
const isc_tpb_lock_write = 11
const isc_tpb_verb_time = 12
const isc_tpb_commit_time = 13
const isc_tpb_ignore_limbo = 14
const isc_tpb_read_committed = 15
const isc_tpb_autocommit = 16
const isc_tpb_rec_version = 17
const isc_tpb_no_rec_version = 18
const isc_tpb_restart_requests = 19
const isc_tpb_no_auto_undo = 20
const isc_tpb_lock_timeout = 21

// Service Parameter Block parameter
const isc_spb_version1 = 1
const isc_spb_current_version = 2
const isc_spb_version = isc_spb_current_version
const isc_spb_user_name = 28 // isc_dpb_user_name

const isc_spb_sys_user_name = 19 // isc_dpb_sys_user_name

const isc_spb_sys_user_name_enc = 31 // isc_dpb_sys_user_name_enc

const isc_spb_password = 29 // isc_dpb_password

const isc_spb_password_enc = 30 // isc_dpb_password_enc

const isc_spb_command_line = 105
const isc_spb_dbname = 106
const isc_spb_verbose = 107
const isc_spb_options = 108
const isc_spb_address_path = 109
const isc_spb_process_id = 110
const isc_spb_trusted_auth = 111
const isc_spb_process_name = 112
const isc_spb_trusted_role = 113
const isc_spb_connect_timeout = 57 // isc_dpb_connect_timeout

const isc_spb_dummy_packet_interval = 58 // isc_dpb_dummy_packet_interval

const isc_spb_sql_role_name = 60 // isc_dpb_sql_role_name

// Database Parameter Block Types
const isc_dpb_version1 = 1
const isc_dpb_page_size = 4
const isc_dpb_num_buffers = 5
const isc_dpb_force_write = 24
const isc_dpb_user_name = 28
const isc_dpb_password = 29
const isc_dpb_password_enc = 30
const isc_dpb_lc_ctype = 48
const isc_dpb_overwrite = 54
const isc_dpb_connect_timeout = 57
const isc_dpb_dummy_packet_interval = 58
const isc_dpb_sql_role_name = 60
const isc_dpb_set_page_buffers = 61
const isc_dpb_sql_dialect = 63
const isc_dpb_set_db_charset = 68
const isc_dpb_process_id = 71
const isc_dpb_no_db_triggers = 72
const isc_dpb_trusted_auth = 73
const isc_dpb_process_name = 74
const isc_dpb_utf8_filename = 77
const isc_dpb_specific_auth_data = 84
const isc_dpb_auth_plugin_list = 85
const isc_dpb_auth_plugin_name = 86
const isc_dpb_config = 87
const isc_dpb_nolinger = 88
const isc_dpb_reset_icu = 89
const isc_dpb_map_attach = 90
const isc_dpb_session_time_zone = 91

// backup
const isc_spb_bkp_file = 5
const isc_spb_bkp_factor = 6
const isc_spb_bkp_length = 7
const isc_spb_bkp_ignore_checksums = 0x01
const isc_spb_bkp_ignore_limbo = 0x02
const isc_spb_bkp_metadata_only = 0x04
const isc_spb_bkp_no_garbage_collect = 0x08
const isc_spb_bkp_old_descriptions = 0x10
const isc_spb_bkp_non_transportable = 0x20
const isc_spb_bkp_convert = 0x40
const isc_spb_bkp_expand = 0x8

// restore
const isc_spb_res_buffers = 9
const isc_spb_res_page_size = 10
const isc_spb_res_length = 11
const isc_spb_res_access_mode = 12
const isc_spb_res_deactivate_idx = 0x0100
const isc_spb_res_no_shadow = 0x0200
const isc_spb_res_no_validity = 0x0400
const isc_spb_res_one_at_a_time = 0x0800
const isc_spb_res_replace = 0x1000
const isc_spb_res_create = 0x2000
const isc_spb_res_use_all_space = 0x4000

// trace
const isc_spb_trc_id = 1
const isc_spb_trc_name = 2
const isc_spb_trc_cfg = 3

// isc_info_svc_svr_db_info params
const isc_spb_num_att = 5
const isc_spb_num_db = 6

// isc_info_svc_db_stats params
const isc_spb_sts_data_pages = 0x01
const isc_spb_sts_db_log = 0x02
const isc_spb_sts_hdr_pages = 0x04
const isc_spb_sts_idx_pages = 0x08
const isc_spb_sts_sys_relations = 0x10
const isc_spb_sts_record_versions = 0x20
const isc_spb_sts_table = 0x40
const isc_spb_sts_nocreation = 0x80

// isc_action_svc_repair params
const isc_spb_rpr_validate_db = 0x01
const isc_spb_rpr_sweep_db = 0x02
const isc_spb_rpr_mend_db = 0x04
const isc_spb_rpr_list_limbo_trans = 0x08
const isc_spb_rpr_check_db = 0x10
const isc_spb_rpr_ignore_checksum = 0x20
const isc_spb_rpr_kill_shadows = 0x40
const isc_spb_rpr_full = 0x80

// Service Action Items
const isc_action_svc_backup = 1
const isc_action_svc_restore = 2
const isc_action_svc_repair = 3
const isc_action_svc_add_user = 4
const isc_action_svc_delete_user = 5
const isc_action_svc_modify_user = 6
const isc_action_svc_display_user = 7
const isc_action_svc_properties = 8
const isc_action_svc_add_license = 9
const isc_action_svc_remove_license = 10
const isc_action_svc_db_stats = 11
const isc_action_svc_get_ib_log = 12
const isc_action_svc_get_fb_log = 12
const isc_action_svc_nbak = 20
const isc_action_svc_nrest = 21
const isc_action_svc_trace_start = 22
const isc_action_svc_trace_stop = 23
const isc_action_svc_trace_suspend = 24
const isc_action_svc_trace_resume = 25
const isc_action_svc_trace_list = 26
const isc_action_svc_set_mapping = 27
const isc_action_svc_drop_mapping = 28
const isc_action_svc_display_user_adm = 29
const isc_action_svc_last = 30

// Transaction informatino items
const isc_info_tra_id = 4
const isc_info_tra_oldest_interesting = 5
const isc_info_tra_oldest_snapshot = 6
const isc_info_tra_oldest_active = 7
const isc_info_tra_isolation = 8
const isc_info_tra_access = 9
const isc_info_tra_lock_timeout = 10

// SQL information items
const isc_info_sql_select = 4
const isc_info_sql_bind = 5
const isc_info_sql_num_variables = 6
const isc_info_sql_describe_vars = 7
const isc_info_sql_describe_end = 8
const isc_info_sql_sqlda_seq = 9
const isc_info_sql_message_seq = 10
const isc_info_sql_type = 11
const isc_info_sql_sub_type = 12
const isc_info_sql_scale = 13
const isc_info_sql_length = 14
const isc_info_sql_null_ind = 15
const isc_info_sql_field = 16
const isc_info_sql_relation = 17
const isc_info_sql_owner = 18
const isc_info_sql_alias = 19
const isc_info_sql_sqlda_start = 20
const isc_info_sql_stmt_type = 21
const isc_info_sql_get_plan = 22
const isc_info_sql_records = 23
const isc_info_sql_batch_fetch = 24

const isc_info_sql_stmt_select = 1
const isc_info_sql_stmt_insert = 2
const isc_info_sql_stmt_update = 3
const isc_info_sql_stmt_delete = 4
const isc_info_sql_stmt_ddl = 5
const isc_info_sql_stmt_get_segment = 6
const isc_info_sql_stmt_put_segment = 7
const isc_info_sql_stmt_exec_procedure = 8
const isc_info_sql_stmt_start_trans = 9
const isc_info_sql_stmt_commit = 10
const isc_info_sql_stmt_rollback = 11
const isc_info_sql_stmt_select_for_upd = 12
const isc_info_sql_stmt_set_generator = 13
const isc_info_sql_stmt_savepoint = 14

const isc_arg_end = 0
const isc_arg_gds = 1
const isc_arg_string = 2
const isc_arg_cstring = 3
const isc_arg_number = 4
const isc_arg_interpreted = 5
const isc_arg_vms = 6
const isc_arg_unix = 7
const isc_arg_domain = 8
const isc_arg_dos = 9
const isc_arg_mpexl = 10
const isc_arg_mpexl_ipc = 11
const isc_arg_next_mach = 15
const isc_arg_netware = 16
const isc_arg_win32 = 17
const isc_arg_warning = 18
const isc_arg_sql_state = 19
