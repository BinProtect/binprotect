BinProtect
----

BinProtect presents a tool capable of transforming programs in binary form
(ELF32) to retrospectively incorporate security mechanisms, which have not been
integrated at compile-time. Inspired by compile-time protection mechanisms,
BinProtect integrates four security hardening measures that are shortly
described in the following: 

* BinProtect hardens calls to unsafe standard C library functions (e.g.
  strcpy(), gets(), sprintf(), ...). For this, binaries are transformed in such
  a way that calls to both statically or dynamically linked standard C library
  are intercepted and replaced by hardened wrapper implementations (the wrapper
  implementations are not part of our project).

* BinProtect transforms binary objects so that they become able to
  detect potential buffer overflows. Therefore, prologue and epilogue
  information of functions is extended. The extended functionality causes the
  prologue to dynamically store functions' return addresses in a dedicated
  memory region (the shadow stack). Whereas, the functions epilogue takes over
  responsibility to detect potential buffer overflows by matching the return
  address with its associated copy on the shadow stack. 

* BinProtect integrates a special ELF program header into binaries so
  that the Linux kernel will mark pages associated with the stack region as
  non-executable. 

* To eliminate malicious manipulation of the Global Offset
  Table (GOT), BinProtect enforces full RELRO (RELocation Read-Only) behavior.
  Therefore, the lazy binding mechanism of the linker is deactivated so that
  all relocations are performed at load-time. Then, parts of the GOT are
  relocated within the binary itself so that they can be marked as read-only
  after performing load-time relocations. Finally, additional functionality is
  injected into binary objects so that the particular memory regions containing
  the GOT can be marked as read-only.  
  
  For additional information you may also consider reading our paper about
  [BinProtect][1].

Requirements
----

* *NOTE:* The current implementation supports only ELF32 binaries and works on
  x86 platforms. 

* In order to successfully compile BinProtect, we assume a valid installation
  of the binary instrumentation framework Dyninst and PatchAPI.


Compilation
----

* <code>make</code>


Command
----

* To be filled...


[1]: https://www.sec.in.tum.de/fatih-kilic/  "BinProtect project description and Paper"

