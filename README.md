<span style="background-color: #226f54; font-size: 125%; padding-top: 1.25%; padding-right: 2.5%; padding-bottom: 1.25%; padding-left: 2.5%; border-radius: 25px;">This project is active: new features are being developed, bugs are being fixed.</span>

# firebird

Firebird database connector for the V language.

## Development

Contributions are very welcome.

- [Issues](https://github.com/einar-hjortdal/firebird/issues)
- [TODO.md](./TODO.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)

All you have to do to contribute to this project is to start a Firebird container like so:

```bash
sudo docker run \
  --rm \
  --detach \
  --name=firebird-server \
  --env=FIREBIRD_ROOT_PASSWORD=rootpwd \
  --env=FIREBIRD_USER=fbusr \
  --env=FIREBIRD_PASSWORD=fbpwd \
  --env=FIREBIRD_DATABASE=firebird.fdb \
  --env=FIREBIRD_DATABASE_DEFAULT_CHARSET=UTF8 \
  --volume=firebird-data:/var/lib/firebird/data \
  --publish=3050:3050 \
  firebirdsql/firebird
```
