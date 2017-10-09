# cryptopals-rust
A rust implementation of the cryptopals challenges.

## Building
- install [rustup](https://www.rustup.rs/)
- `cargo build` or `cargo build --release` (building release is slow, but runs much faster)
- `./target/debug/cryptopals [OPTIONS]` or `./target/release/cryptopals [OPTIONS]`
- make sure you run this from the root of this repo, as it requires the `data` folder.

## Running
```
cryptopals 1.0
Nicholas Dujay <nickdujay@gmail.com>
Runs Matasano's cryptopals challenges

USAGE:
    cryptopals [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --challenge <challenge>    Configures which challenge to run.
```
