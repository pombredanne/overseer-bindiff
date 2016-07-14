# Overseer plugin for binary, enrypted updates
This binary generates the updates for the given binary,
and the `./fetcher` package is a drop-in replacement
for overseer.Fetcher, to download these updates through HTTP.

## Usage
1. *generate <mybin>*: generates the binaries under `plugin`.

1. *genkeys*: generates the two public-private keypairs, one for the publisher
(encrypting the diffs and the binary, and also signing the manifest), and
one for the consumer (which should be included with the binary).

1. *printkeys*: prints the publisher's public- and the consumer's private key,
to be included in the binary. The `--go-out` option modifies the output to
be Go source code.
