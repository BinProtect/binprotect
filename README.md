BinProtect
==========

Buffer overflow vulnerabilities present a common threat. To encounter this
issue, operating system support and compile-time security hardening measures
have been introduced.  Unfortunately, these are not always part of the shipped
object code. We present BinProtect, a binary rewriting tool, capable of
retrospectively protecting binaries, which have not been sufficiently protected
at compile-time. To achieve this, we do not need source code or any additional
information.

The security mechanisms to be retrospectively injected into binaries covered
by BinProtect comprise: 

* NX: force the loader to mark the stack (and heap) segment to be
  non-executable (assuming that all library dependencies of the binary do not
  require an executable stack).
* RELRO: force all relocations to be resolved before the start of the
  application and stored within the GOT. The complete GOT table is then marked
  as read-only to prevent e.g. return-to-libc attacks (assuming partial RELRO).
* FORTIFY_SOURCE: intercept "unsafe" library function calls and replace these
  with safe implementations. 
* StackProtect: modify functions in such a way, so that they become able to
  check the integrity of their stack frames. For this, a shadow stack mechanism
  is introduced, which is used for temporary storage of return addresses of
  currently active activation records. These addresses are checked upon every
  function exit with the actual return address for integrity. 


