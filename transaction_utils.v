module firebird

import arrays

const partial_tpb = [u8(isc_tpb_version3), u8(isc_tpb_write), u8(isc_tpb_wait)]

fn get_tpb(isolation_level int) []u8 {
	match isolation_level {
		isolation_level_read_commited_legacy {
			return arrays.concat(partial_tpb, u8(isc_tpb_read_committed),
				u8(isc_tpb_no_rec_version))
		}
		isolation_level_read_commited {
			return arrays.concat(partial_tpb, u8(isc_tpb_read_committed), u8(isc_tpb_rec_version))
		}
		isolation_level_repeatable_read {
			return arrays.concat(partial_tpb, u8(isc_tpb_concurrency))
		}
		isolation_level_serializable {
			return arrays.concat(partial_tpb, u8(isc_tpb_consistency))
		}
		isolation_level_read_commited_ro {
			return [
				u8(isc_tpb_version3),
				u8(isc_tpb_read),
				u8(isc_tpb_wait),
				u8(isc_tpb_read_committed),
				u8(isc_tpb_rec_version),
			]
		}
		else {
			return []u8{}
		}
	}
}
