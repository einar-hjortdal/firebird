module tests

pub const protocol = 'firebird://'
pub const user = 'fbusr'
pub const password = 'fbpwd'
pub const host = '127.0.0.1:3050'
pub const database = '/var/lib/firebird/data/firebird.fdb'
pub const url = '${protocol}${user}:${password}@${host}${database}'
