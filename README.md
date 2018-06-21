## Interview CSPRNG

Salsa20-based RNG that will output a pseudorandom keystream similar to running `cat /dev/random` on a linux machine

### Running the sample

Requires oracle/openjdk 8.

Run it with `java -jar random.jar` for an endless keystream, or `java -jar random.jar <n>` for `n` random bytes.

### Building

Use [sbt](https://github.com/sbt/sbt), and run `assembly` to generate `random.jar` under the `target` folder.

### How it works

The `Salsa20CSPRNG` class implements the [Salsa20](https://cr.yp.to/snuffle/spec.pdf) spec. 
Instead of message xor keystream, however, it simply outputs the keystream. It outputs at most 2^64 bytes before
it reseeds.

Initial and subsequent reseeding is done using tcpdump. However, tcpdump output is rather predictable (the basic output)
is a timestamp for the first few letters. Thus, we ensure we consume at least 1kb of packet data, then pick a
random point in the text stream (with a non-CSPRNG, so default java Random, whose seeding depends on the system time in ns),
and select from there. This randomizes the seeding from our "random" source a lot more than not 
skipping ahead at all.

The implementation of the cipher itself is ugly, but it approaches what it would look like in low level C. 
However, the interface to the PRNG is a pure `IO` action