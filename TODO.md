# TODO

## Priorities

### Highest

- connect to Firebird
  - ~~Secure Remote Password~~
  - ~~Encrypt with chacha20~~
- issue commands
- parse responses

### High

- logging
- connection pool

### Medium

- optimize performance
- never panic

### Low

I do not use the following features and will not support them. If you would like to support any of them, 
please open a pull request.

- embedded
- decfloat
- int128
- events
- charset other than UTF8
- Firebird versions other than >= 5
- protocol versions < 18
- `Legacy_Auth` auth plugin
- `Arc4` wire encryption plugin