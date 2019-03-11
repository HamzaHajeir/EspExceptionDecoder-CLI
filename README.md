# ESP8266/ESP32 Exception Stack Trace Decoder CLI version

Port of https://github.com/me-no-dev/EspExceptionDecoder to CLI.

## Usage
| Description | Environment Variable | CLI argument |
| -- | -- | -- |
| ELF file| ELF_FILE| -e |
| Xtensa GDB file | XTENSA_GDB | -g |
| Exception File| EXP_FILE | -x (default homedirectory/exception.txt)|
| Output file | DECODE_FILE | -o (default stdout) |

Either environment variable or CLI argument can be used.

CLI arguments take priority over environment variables.

## Credits and license

- Copyright (c) 2015 Hristo Gochkov (ficeto at ficeto dot com)
- Modified by Rushikesh Patel 2018 (https://gituhb.com/luffykesh)
- Licensed under GPL v2 ([text](LICENSE))