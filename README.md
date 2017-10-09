# BLAKE2b

Standalone implementation of BLAKE2b cryptographic hash function in Java.

[![Maven Central](https://img.shields.io/maven-central/v/com.rfksystems/blake2b.svg?style=flat-square)](http://mvnrepository.com/artifact/com.rfksystems/blake2b)

## Example usage

See [com.rfksystems.blake2b.Blake2BTest](src/test/java/com/rfksystems/blake2b/Blake2BTest.java) for example use.

### Security provider

This package includes implementation of `java.security.Provider` in `com.rfksystems.blake2b.security.Blake2bProvider`
class. You can register this provider by calling `Security.addProvider(new Blake2bProvider());`.

`Blake2bProvider` exposes following digest functions

- `BLAKE2B-160`
- `BLAKE2B-256`
- `BLAKE2B-384`
- `BLAKE2B-512`

## Installation

### Maven

```xml
<dependency>
    <groupId>com.rfksystems</groupId>
    <artifactId>blake2b</artifactId>
    <version>${blake2b.version}</version>
</dependency>
```

### License

Apache License, Version 2.0
