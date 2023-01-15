# Hardware trust

Reliable trust in a device's hardware is the basis of a growing set of features,
for example remote key provisioning.

## `libhwtrust`

The library for handling, inspecting and validating data realted to the hardware
root-of-trust and the features that rely on it is `libhwtrust`.

## `hwtrust`

There is a command-line utility that provides easy access to the logic in
`libhwtrust` called `hwtrust`. Run `hwtrust --help` to see a list of its
functions.

### Verifying DICE chains

`hwtrust` can be used to validate that a DICE chain is well-formed and check
that the signatures verify correctly. To do so, place the CBOR-encoded DICE
chain in a file, e.g. `chain.bin`, then call the tool.

```shell
hwtrust verify-dice-chain chain.bin
```

The exit code is zero if the chain passed verification and non-zero otherwise.
