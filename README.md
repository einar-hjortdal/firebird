# firebird

Firebird database connector for the V language.

## Development

- [Issues](https://github.com/einar-hjortdal/firebird/issues)
- [TODO.md](./TODO.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)

```bash
# Start a firebird container
podman run \
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
    ghcr.io/fdcastel/firebird
```
