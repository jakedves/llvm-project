# BOLT-based binary analysis

As part of post-link-time optimizing, BOLT needs to perform a range of analyses
on binaries such as reconstructing control flow graphs, and more.

The `llvm-bolt-binary-analysis` tool enables running requested binary analyses
on binaries, and generating reports. It does this by building on top of the
analyses implemented in the BOLT libraries.

## Background and motivation

### Security scanners

For the past 25 years, a large numbers of exploits have been built and used in
the wild to undermine computer security. The majority of these exploits abuse
memory vulnerabilities in programs, see evidence from
[Microsoft](https://youtu.be/PjbGojjnBZQ?si=oCHCa0SHgaSNr6Gr&t=836),
[Chromium](https://www.chromium.org/Home/chromium-security/memory-safety/) and
[Android](https://security.googleblog.com/2021/01/data-driven-security-hardening-in.html).

It is not surprising therefore, that a large number of mitigations have been
added to instruction sets and toolchains to make it harder to build an exploit
using a memory vulnerability. Examples are: stack canaries, stack clash,
pac-ret, shadow stacks, arm64e, and many more.

These mitigations guarantee a so-called "security property" on the binaries they
produce. For example, for stack canaries, the security property is roughly that
a canary is located on the stack between the set of saved registers and the set
of local variables. For pac-ret, it is roughly that either the return address is
never stored/retrieved to/from memory; or, there are no writes to the register
containing the return address between an instruction authenticating it and a
return instruction using it.

From time to time, however, a bug gets found in the implementation of such
mitigations in toolchains. Also, code that is written in assembler by hand
requires the developer to ensure these security properties by hand.

In short, it is sometimes found that a few places in the binary code are not
protected as well as expected given the requested mitigations. Attackers could
make use of those places (sometimes called gadgets) to circumvent the protection
that the mitigation should give.

One of the reasons that such gadgets, or holes in the mitigation implementation,
exist is that typically the amount of testing and verification for these
security properties is limited to checking results on specific examples.

In comparison, for testing functional correctness, or for testing performance,
toolchain and software in general typically get tested with large test suites
and benchmarks. In contrast, this typically does not get done for testing the
security properties of binary code.

Unlike functional correctness where compilation errors result in test failures,
and performance where speed and size differences are measurable, broken security
properties cannot be easily observed using existing testing and benchmarking
tools.

The security scanners implemented in `llvm-bolt-binary-analysis` aim to enable
the testing of security hardening in arbitrary programs and not just specific
examples.

### Pointer Authentication

[Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
is intended to make it harder for an attacker to replace pointers at run time.
This is achieved by making it possible for the compiler or the programmer to
produce a *signed* pointer from a raw one, and then to probabilistically
*authenticate the signature* at another site in the program.
On AArch64 this is achieved by injecting a cryptographic hash, called a
["Pointer Authentication Code" (PAC)](https://llsoftsec.github.io/llsoftsecbook/#pointer-authentication),
to the upper bits of the pointer.
While this approach can be applied to any pointers in the program, the most
frequent use case, at least in C and C++, is protecting the code pointers.
The language rules for such pointers are more restrictive, thus allowing the
compiler to implement various hardenings transparently to the programmer.

Probably the most simple variant of hardening based on Pointer Authentication is
`pac-ret`, a security hardening scheme implemented in compilers such as GCC and
Clang, using the command line option `-mbranch-protection=pac-ret`. This option
is enabled by default on most widely used Linux distributions.
The hardening scheme mitigates
[Return-Oriented Programming (ROP)](https://llsoftsec.github.io/llsoftsecbook/#return-oriented-programming)
attacks by making sure that return addresses are only ever stored to memory
protected by pointer signing. This makes it substantially harder for attackers
to divert control flow by overwriting a return address with a different value.

## Pointer Authentication validator

Pointer Authentication analysis is able to search for a number of gadget kinds,
with the specific set depending on command line options:
* non-protected return instructions
* non-protected branch or call instructions
* signing of untrusted values (signing oracles)
* ... and a few other kinds

Validation is performed by `llvm-bolt-binary-analysis` on a per-function basis.
First, the register properties are computed by analyzing the function as a whole.
Then, the instructions are considered in isolation. For each kind of gadget,
the set of susceptible instructions is computed. The properties of input or
output registers of each such instruction are analyzed and reports are produced
for unsafe instruction usage.

Each gadget kind that is searched for can be characterized by
* the set of instructions to analyze
* the properties of input or output operands to check

Currently, three properties can be computed for each register at any given
program point:
* **"trusted"** - the register is known not to be attacker-controlled, either because
  it successfully passed authentication or because its value was materialized
  using an instruction sequence that an attacker cannot tamper with
  * **"safe-to-dereference"** (sometimes referred to as "s-t-d" below) - a weaker property is that the register can be
    controlled by an attacker to some extent, but any memory access using a value
    crafted by an attacker is known to result in access to an unmapped memory
    ("segmentation fault"). This allows implementing failed authentication
    as returning a known-broken memory address, but requires extra care to be
    taken when implementing operations like re-signing a pointer with a different
    signing schema. If any failed authentication is guaranteed to terminate the
    program abnormally, then "safe-to-dereference" and "trusted" properties
    are equivalent.
* **"cannot escape unchecked"** - at every possible execution path after this point,
  it is known to be impossible for an attacker to determine that the value is
  a result of a failed authentication operation (for example, the register is
  zeroed, or its value is checked to be valid, so that failure results in
  immediate abnormal program termination).

### Return address protection (before return instruction)

**Instructions:** Return instructions without built-in authentication:
either `ret` (implicit `x30` register) or `ret <reg>`, but not `retaa` and
similar instructions.

**Property:** The register holding the return address must be safe-to-dereference.

**Notes:** Cross-exception-level return instructions are not analyzed yet.

A report is generated for a return instruction whose destination is possibly
attacker-controlled.

**Examples:**
```
authenticated_return:
  pacibsp
  ; ...
  ; ... some code here ...
  ; ...
  retab ; Built-in authentication, thus out of scope.

good_leaf_function:
  ; x30 is implicitly safe-to-dereference (s-t-d) and trusted at function entry.
  mov     x0, #42
  ; x30 was not written by this function, thus remains s-t-d.
  ret

good_non_leaf_function:
  pacibsp

  ; Spilling signed return address.
  stp     x29, x30, [sp, #-16]!
  mov     x29, sp

  bl      @callee

  ; Re-loading signed return address.
  ; LDP writes to x30 and thus resets it to neither s-t-d nor trusted state.
  ldp     x29, x30, [sp], #16

  ; Checking that signature is valid.
  ; AUTIBSP sets "s-t-d" property of x30, but not "trusted" (unless FEAT_FPAC
  ; is known to be implemented).
  autibsp

  ; x30 is s-t-d at this point.
  ret

bad_spill:
  ; x30 is implicitly s-t-d at function entry.
  stp     x29, x30, [sp, #-16]!
  mov     x29, sp

  bl      @callee ; Spilled x30 may have been overwritten on stack.

  ; Writing to x30 resets its s-t-d property.
  ldp     x29, x30, [sp], #16
  ; x30 is unsafe by the time it is used by ret, thus generating a report.
  ret

bad_clobber:
  pacibsp
  ; ...
  ; ... some code here ...
  ; ...
  autibsp
  mov     x30, x1
  ; The value in LR is unsafe, even though there was autibsp above.
  ret
```

### Return address protection before tail call

**Instructions:** Branch instructions (both direct and indirect, regular or
with built-in authentication), identified as tail calls either by BOLT or by
PtrAuth gadget scanner's heuristic.

**Property:** `x30` must be trusted.

**Notes:** Heuristics are involved to classify instructions either as a tail
call or as another kind of branch (such as jump table or computed goto).

A gadget kind related to unprotected return is tail call performed with an
untrusted address in `x30` like this:

```
untrusted_tail_call:
  stp     x29, x30, [sp, #-16]!
  mov     x29, sp
  bl      @callee
  ldp     x29, x30, [sp], #16
  ; x30 is neither trusted nor safe-to-dereference at this point.
  b       @tail_callee

tail_callee:
  pacibsp
  ; ...
```

While `b tail_callee` instruction itself does not use the value stored in `x30`,
calling a function with untrusted address in `x30` violates the assumption that
return address is trusted at least at the function entry.

Even though `x30` is likely to be safe-to-dereference before exit from a function
(whether via return or tail call) in a consistently pac-ret-protected program,
with respect to this gadget kind it further must be fully "trusted".
With `x30` being safe-to-dereference, but not fully trusted at the entry to the
tail callee, the subsequent `pacibsp` instruction may act as a [signing oracle](#signing-oracles).
Properly mitigating this issue would usually require inserting an explicit
check after a regular authentication instruction, which may be either too
expensive (if a fully-generic XPAC-based sequence is being used) on one hand,
or not required at all (if `FEAT_FPAC` is known to be implemented) on the other hand.

### Indirect branch / call target protection

**Instructions:** Indirect call and branch instructions without built-in
authentication: either `blr <reg>` or `br <reg>`, but not `blraa`, `braa`
and similar instructions.

**Property:** Call or branch target register must be safe-to-dereference.

Report is generated for an indirect branch or call instruction whose destination
is possibly attacker-controlled.

**Examples:**

```
direct_call:
  ; ...
  bl     @callee ; Direct call, thus out of scope.
  ; ...

authenticated_call:
  ; ...
  ldr     x2, [x1]
  blraa   x2, x1   ; Built-in authentication, thus out of scope.
  ; ...

good_call:
  ; ...
  ldr     x2, [x1]
  autia   x2, x1
  blr     x2
  ; ...

bad_call:
  ; ...
  ldr     x2, [x1]
  autia   x2, x1
  ; Store unprotected address.
  stp     x2, [x3]
  ; ...
  ; The callee address may have been overwritten in memory.
  ldr     x2, [x3]
  blr     x2
  ; ...
```

### Signing oracles

**Instructions:** Address-signing instructions.

**Property:** The address being signed must be trusted.

Reports signing of untrusted values, as this could make arbitrary and possibly
attacker-controlled values indistinguishable from perfectly trusted and protected ones.

**Examples:**

```
good_sign_constant:
  ; ...
  adrp    x0, @sym
  add     x0, x0, :lo12:@sym
  pacda   x0, x1
  ; ...

good_resign:
  ; ...
  autda   x0, x1
  ; x0 is s-t-d here.
  ldr     x2, [x0]
  ; If we got here without crashing on the above LDR, x0 is fully trusted.
  pacdb   x0, x1
  ; ...

bad_resign_if_not_fpac:
  ; ...
  autda   x0, x1
  ; x0 is only s-t-d, but not trusted here, unless autda raises an error on failure.
  pacdb   x0, x1
  ; ...

very_bad_function:
  pacda   x0, x1
  ret
```

### Authentication oracles

**Instructions:** Standalone authentication instructions: `autda`, `autdb`, etc.
(i.e. not built-into corresponding memory-accessing instructions, such as
`ldraa` or `blraa`).

**Property:** The **result** of authentication must be written to a register
that cannot escape unchecked.

TODO

## Usage

```
llvm-bolt-binary-analysis --scanners=<list> [options] <binary>
```

The `--scanners=` option accepts a comma-separated list of analyses to run on
the provided binary. The binary to be analyzed can be either ELF executable or
shared object.

In addition to options printed by `llvm-bolt-binary-analysis --help-hidden`,
other relevant BOLT options can generally be passed, see `llvm-bolt --help-hidden`.

The only analysis which is currently implemented is validation of Pointer
Authentication hardening applied to the binary.
The specific set of gadget kinds which are searched for depends on command line
options. Each gadget found by PtrAuth gadget scanner results in a plain text
report printed at the end of analysis.
Furthermore, an attempt is made to provide an extra information on the
instructions that made the register not safe.
Please note that this extra information is provided on a best-effort basis and
is not expected to be as accurate as the reports themselves.

Here is an example of the report:

```
GS-PAUTH: signing oracle found in function function_name, basic block .LBB08, at address 102b8
  The instruction is     000102b8:      pacda   x0, x1
  The 1 instructions that write to the affected registers after any authentication are:
  1.     000102b4:      ldr     x0, [x1]
  This happens in the following basic block:
    000102b4:   ldr     x0, [x1]
    000102b8:   pacda   x0, x1
    000102bc:   ret
```

A similar report without the associated extra information is along these lines:

```
GS-PAUTH: signing oracle found in function function_name, basic block .LBB016, at address 10384
  The instruction is     00010384:      pacda   x0, x1
  The 0 instructions that write to the affected registers after any authentication are:
```

Furthermore, a ", basic block `<name>`" part is omitted in a report, if BOLT was
unable to reconstruct control-flow graph for the particular function:

```
GS-PAUTH: signing oracle found in function function_name_nocfg, at address 10510
  The instruction is     00010510:      pacda   x0, x1
  The 0 instructions that write to the affected registers after any authentication are:
```

The analysis is likely to be less precise when CFG information is absent or
incomplete.

## How to add your own binary analysis

_TODO: this section needs to be written. Ideally, we should have a simple
"example" or "template" analysis that can be the starting point for implementing
custom analyses_












##### Known false positives or negatives

The following are current known cases of false positives:

1. Not handling "no-return" functions. See issue
   [#115154](https://github.com/llvm/llvm-project/issues/115154) for details and
   pointers to open PRs to fix this.
2. Not recognizing that a move of a properly authenticated value between registers,
   results in the destination register having a properly authenticated value.
   For example, the scanner currently produces a false negative for the following
   code sequence:
   ```
        autiasp
        mov     x16, x30
        ret     x16
   ```

The following are current known cases of false negatives:

1. Not handling functions for which the CFG cannot be reconstructed by BOLT. The
   plan is to implement support for this, picking up the implementation from the
   [prototype branch](
   https://github.com/llvm/llvm-project/compare/main...kbeyls:llvm-project:bolt-gadget-scanner-prototype).
