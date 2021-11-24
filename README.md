# kotlin-cli-bazel-triple-des-encryption-salted-password

## Description
A demo for 3-DES encryption of a password.
3-DES is a 128 byte encryption.

Uses a 256 byte AES generated key
for the md5 digest password.

## Tech stack
- kotlin
- bazel

## Docker stack
- l.gcr.io/google/bazel:latest

## To run
`sudo ./install.sh -u`

## To stop (optional)
`sudo ./install.sh -d`

## For help
`sudo ./install.sh -h`

## Credit
[Code concept] (https://stackoverflow.com/questions/20227/how-do-i-use-3des-encryption-decryption-in-java)
