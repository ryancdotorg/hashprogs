These are some programs I wrote because I needed them. I have posted them in
the hopes that they may be useful.

---

`allsum` - You know about `md5sum`, `sha1sum`, `sha256sum`, `b2sum`, etc,
right? This is similar, but it runs all the hashes available via OpenSSL’s
EVP digest API.

Usage: `allsum [FILES]`, `allsum < FILE`, or `COMMAND | allsum`

---

`hashln` - Computes the hash of a string supplied as an argument or lines of
a file.

Usage: `hashln ALGO STRING`, `hashln < FILE`, or `COMMAND | hashln`

---

`dgstmv` - Name (or rename) a file based on its hash. Useful for malware
samples and disk images.

Usage: - `dgstmv ALGO SRC_FILE DST_FILE_TEMPLATE`, `dgstmv ALGO
DST_FILE_TEMPLATE < FILE`, or `COMMAND | dgstmv ALGO DST_FILE_TEMPLATE`

Templates:

* `%h` - The hash output in lowercase hex.
* `%H` - The hash output in uppercase hex.
* `%7h` or `%7H` - The first seven nybbles of the hash output in hex, any
  number can be used.
* `%-7h` or `%-7H` - The last seven nybbles of the hash output in hex, any
  number can be used.

---

More to come?
