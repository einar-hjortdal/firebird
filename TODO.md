# TODO

## Priorities

### Highest

- ~~connect to Firebird~~
- ~~support Secure Remote Password auth plugin~~
- ~~support arc4 crypt plugin~~
- ~~perform queries~~
- parse responses

### High

- never panic

### Medium

- ~~support chacha crypt plugin~~
- support chacha64 crypt plugin <!-- https://github.com/vlang/v/issues/23904 -->
- logging
- optimize performance

### Low

I do not use the following features and will not support them. If you would like this project to support 
any of them, please open a pull request.

- embedded
- numeric
- decimal
- decfloat
- int128
- batches
- services
- events
- charset other than UTF8
- Firebird versions other than >= 5
- protocol versions < 18
- Legacy_Auth auth plugin
