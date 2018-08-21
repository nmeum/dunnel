# dunnel

A less bloated version of `stunnel(1)` for [DTLS][RFC6347].

# Status

Unmaintained and totally unfinished. For instance, only 1-to-1
relationships are supported currently. Consider this an experiment which
still needs a lot of work and care.

# Installation

**TODO**

# Usage example

Generate key/identity files:

	$ printf Client_identity > identity
	$ printf secretPSK > key

Client usage example:

	$ cd tinydtls/tests
	$ ./dtls-server -A ::1 -p 2323 &
	$ ./dunnel -a ::1 -p 4242 -i identity -k key ::1 2323 &
	$ busybox nc -u ::1 4242

Server usage example:

	$ busybox nc -u -l -p 4242 ::1 &
	$ ./dunnel -s -a ::1 -p 4242 -i identity -k key ::1 2342 &
	$ cd tinydtls/tests
	$ ./dtls-client -i ../../identity -k ../../key ::1 2342


# License

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.

[RFC6347]: https://tools.ietf.org/html/rfc6347
