# TODO

## Priorities

### Highest

- [x] connect to Firebird
- [x] support Secure Remote Password auth plugin
- [x] support arc4 crypt plugin
- [x] support chacha crypt plugin
- [x] support chacha64 crypt plugin
- [x] perform queries
- [x] parse responses

### High

- [x] queries with parameters
- [x] date
- [x] time
- [x] connection pool
- [ ] tests
- [ ] never panic

### Medium

- [ ] logging
- [ ] optimize performance

### Low

- [ ] add missing isc_error constants
- [ ] parse isc_error message parameters

### Not planned

I do not use the following features and will not support them. If you would like this project to support 
any of them, please open a pull request.

- embedded
- types: 
  - numeric
  - decimal
  - extended time with timezone
  - extended timestamp with timezone
  - decfloat
  - int128
- stored procedures
- batches
- services
- events
- charset other than UTF8
- Firebird versions other than >= 5
- protocol versions < 18
- Legacy_Auth auth plugin
