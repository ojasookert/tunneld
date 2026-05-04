# tunneld

Self-hosted HTTP reverse-tunnel server. Random four-word subdomains, single bearer token, h2 reverse-roles transport.

## Use

```sh
curl -fsSL https://tunnel.le.ht/install | sh
TUNNELD_SECRET=… tunneld client --local 127.0.0.1:3000
```

Prints a URL like `https://flower-geek-episode-thirst.tunnel.le.ht`.

## Build

```sh
cargo build --release
```

## License

MIT.
