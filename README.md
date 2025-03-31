#Infinite Cipher

The Infinite Cipher is a family of arbitrarily high strength ciphers, ranging from an everyday performance balanced 65536 bits to whatever number you can think of (as long as it is a power of 2 and your computer has sufficient memory).

Due to relying on the Algorithm Enhancement Stuff found in modern processors the Infinite Cipher easily deliver speeds competitive with popular implementations of lesser ciphers. Furthermore the built-in authentication is good for both speed and ease of use.

The Infinite Cipher has been a favourite amongst many users of homemade headgear since its release on April 1st 2025.

##Specification

In addition to this specification it is recommended to read the `infinite512.c` implementation file.

Each member of the cipher family is identified by two numbers, a strength level `s`, and a tag size `t`. `s` must be at least `16`, and `t` must be at least `9` and lower than `s`. The nominal strength of the cipher is `2^s` bits, and the size of the generated authentication tag is `2^t` bits. The security claim of `2^s` bits assume that an attacker has access to no more than `2^(16\*s)` known or chosen plaintext blocks.

While infinitely many members of the Infinite Cipher family are defined, an implementation may choose to only implement a finite number of them.

###Scramble

The core of an Infinite Cipher member is the Scramble function, it takes a buffer (the `Base`) of size `2^(s-2)` bytes and permutes it in a chaotic fashion, it also takes as input a `Tweak` number that used in the permutation. The `Base` is conceptually divided into 128 bit words, all operations are performed on chunks of 4 words aka 512 bit superwords, conveniently equivalent to AVX512 registers. A few constants are generated based on `s`:

Round count `r = floor(s^2 / 8)`
Round length `l = 4 \* roundToOdd(φ^-2 \* 2^(s-10))`
Fetch offset `o = 4.5\*l + 2^(s-7) + 18`

The first 11 superwords of the `Base` are moved to a separate buffer called the `State`, and are referred to as state0 through state10. Three pointers into the `Base` are tracked:

Store pointer, initially points to word 0 of the `Base`.
Load pointer, initially points to word 44 of the `Base`.
Fetch pointer.

The pointers are moved throughout the computation, the `Base` is considered to wrap around, so whenever a pointer would point outside the `Base` it should be moved to the equivalent location. Conceptually the Store and Load pointers delimit the hole left when the `State` was moved, this conceptual hole will remain throughout the computation, but move along with the pointers.

The follow operations are used in the computation:
`XOR` - The bitwise exclusive or is performed on two superwords, returning a new superword.
`ADD` - Two superwords are each considered as 16 little endian 32 bit numbers, they are added together pairwise with two's complement overflow, producing 16 new numbers that form a new superword.
`AES` - A superword is considered as four 128 bit words, each word is transformed by applying a single AES encryption round, without the AddRoundKey step.

`r` rounds run as follows:
	- The Store and Load pointers start each round at the value they had at the end of the previous round.
	- The Fetch pointer is set to be `o` words ahead of the Store pointer.
	- The lower 128 bit word of `state0` is `XOR`ed with the lower 128 bits of the `Tweak` in little endian.
	- Similarly the following three words of `state0` are `XOR`ed with the lower 128 bits of `Tweak+1`, `Tweak+2` and `Tweak+3` respectively. If `Tweak+3` is too large to fit in a 128 bit value then the overflowing bits are `XOR`ed into `state1`, then `state2` etc. If 1408 bits isn't enough continue with superwords from the `Base`, starting at the Load pointer. (While there is no definite limit to how large the `Tweak` value may get, practical implementations can generally compute a bound that will not be reached before running out of address space.)
	- Then `l` steps run as follow:
		- Superword `ld` is loaded from the load pointer.
		- Superword `st` is produced by `ADD`ing `ld` to `state3`.
		- Superword `ft` is loaded from the fetch pointer.
		- `st` is stored to the store pointer.
		- `ld` is `XOR`ed into `state0`.
		- `state0` as `AES`ed.
		- `state3` is `XOR`ed into `state0`.
		- `st` is `XOR`ed into `state1`.
		- `state1` as `AES`ed.
		- `ft` is `XOR`ed into `state1`.
		- `state3` is `ADD`ed to `state2`.
		- `ld` and `st` are each moved 4 words forward.
		- `ft` is moved 5 words backwards.
		- The `State` is rotated 3 superwords backwards, so `state0` becomes `state8`, `state1` becomes `state9`, `state2` becomes `state10`, `state3` becomes `state0` etc.

###Initialisation

All Infinite Cipher members accept an arbitrary length key, the key is transformed into a fixed length `Lid`. First a buffer of length `2^(s-2)` bytes is zeroed, then for each `2^(s-2)` bytes of the key those bytes are `XOR`ed into the buffer, and the buffer is Scrambled with `Tweak` `1+4\*blockId`, where `blockId` is `0` for the first key block, `1` for the following etc. The final block is padded with zeroes at the end, and the final `Tweak` `is 1+4\*blockId+4\*blockLength`. If the key length is zero it is treated as one length 0 block, otherwise there will never be a length 0 block. The final state of the buffer is the `Lid`.

###Encryption

The encryption procedure requires a nonce, the nonce must be no longer than `2^(s-2)` bytes, and must be unique for each message. A `Mask` buffer of length `2^(s-2)` bytes is created by XORing the `Lid` with the zero padded nonce and Scrambling the result using `Tweak` `3+4\*nonceLength`. A `Tag` buffer of size `2^(t-3)` bytes is zeroed.

The plaintext is divided into blocks of length `2^(s-2)` bytes. For each block the cyphertext is generated by `XOR`ing the plaintext block with the `Mask` and the `Lid`. The `Mask` is then updated by `XOR`ing it with the plaintext block and Scrambling it with `Tweak` `2\*blockId`, where `blockId` is `0` for the first block, `1` for the next etc. Then the `Tag` buffer is `XOR`ed with the first `2^(t-3)` bytes of the resulting `Mask` buffer. The final block is zero padded and the `Tweak` value is `2\*blockId+2\*blockLength`. The final ciphertext block is cropped to the length of the plaintext block. Note that the final `Mask` buffer state is not used for encrypting the plaintext, but must still be generated in order to compute the `Tag`. If the plaintext is length zero, then zero blocks are processed and the `Tag` is set using the initial value of the `Mask` buffer.

###Decryption

Decryption is done almost the same way as encryption, except that the plaintext must be computed by XORing the cyphertext, the `Lid` and the `Mask`. Decryption must also generate a `Tag`, compare it to the provided `Tag`, and reject the message if they do not match.

##Implementation

This initial implementation of the Infinite Cipher is limited to a maximum strength level of 62, delivering a strength of 4611686018427387904 bits. While one could desire a higher level, this will require a greater than 64 bit memory system for realistic use. As such memory systems are virtually non-existent at the moment I have decided to focus my initial effort on 64 bit systems.

Exactly one of `infinite512.c` and `infinite128.c` must be included in a project. `infinite512.c` is generally faster, but requires AVX512. `infinite128.c` uses only 128 bit registers and will run on most modern X86 and high end Arm chips. `infinite.h` works as header for either implementation. `test.c` is as the name implies only for testing the implementation, it should not be included in any other project.

This implementation relies on a buffer structure object that is passed around as a void pointer. The size of the buffer structure depend on the chosen strength level, the `INFINITE_BUFFERSTRUCTURESIZE(s)` macro has been included for easily calculating this size. The buffer structure is initialised with an s and a t parameter, along with a key. The buffer structure can be passed to the encrypt and decrypt functions in order to encrypt and decrypt with that key. A buffer structure can after a single initialisation be used any number of times, but may only be used by a single thread at once.

###Compilation

Example compiler invocations for the test code:

```
gcc test.c infinite128.c -maes -O3
gcc test.c infinite128.c -maes -mavx -O3
gcc test.c infinite512.c -mavx512f -mvaes -O3
```
