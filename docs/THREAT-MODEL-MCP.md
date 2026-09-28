# Threat model: the MCP adapter

Milestone 05 names a threat review of file-path and output handling as a
prerequisite. This is it. It covers the adapter only; the core's own boundaries
— plan JSON, intent JSON, the Evidence Bundle — are reviewed in their own
milestones and are assumed here.

## What changes when the adapter exists

Until now every input arrived from a person at a terminal, who chose the two
files and read the answer. The adapter is driven by a coding agent: the paths
are chosen by a model, from text that may itself have come from a repository, an
issue, or a plan. Two things follow, and everything below is one of them.

**The caller is not trusted to choose what is read.** A path is an instruction
from something that may have been instructed by someone else.

**The caller repeats what it is told.** Anything in a tool result may end up in
a model's context, in a commit message, or in a comment on a pull request. A
value this build declines to print is a value it must also decline to return.

## Assets

- The plan and the contract the caller names. These are the point; returning
  what they say is the job.
- Every other file the process can read. The verifier runs with the developer's
  own credentials on their own machine, so the set is large: private keys,
  environment files, other repositories.
- Values inside a plan that Terraform marked sensitive.
- The machine's availability. A server that hangs or exhausts memory takes the
  agent's session with it.

## Trust boundaries

| Boundary | What crosses it | Who wrote it |
| --- | --- | --- |
| stdin | JSON-RPC messages | the client, on behalf of a model |
| the filesystem | two files named by the caller | whoever wrote them |
| stdout | one JSON-RPC message per request | this build |

There is no fourth. The server opens no socket, starts no process, and loads no
code it did not ship with.

## Threats and what answers them

### A path that names a file outside the project

The most direct attack: `analyze_change` with `/Users/someone/.ssh/id_ed25519`
as the plan. It would fail to parse, but the parser's diagnostics name byte
offsets and, on some paths, quote a token — enough to confirm a file exists and
something about its shape.

Answered by `internal/pathguard`: every path is resolved and compared against
roots given at startup, and there is no default root. The refusal is the same
for a file that is outside the roots and one that is outside them and absent, so
a refusal cannot be used to ask whether a file exists.

### A symbolic link inside the project that points out of it

A repository can contain a link. `git` will happily carry one, so a plan named
`./plan.json` inside an allowed root can be a link to anything the process can
read — and a check on the string would pass it.

Answered by `os.Root`, which walks the path itself and refuses one that leaves
the directory it was opened on. The check is about which file is opened, not
about how it was spelled.

### A symbolic link installed while the file is being opened

The version of this document written before the adapter was reviewed said the
link check answered this. It did not. The guard approved a *name* and the
verifier opened that name afterwards, so a regular file could become a link in
between: the check passed and the read left the root. Independent review did it
eight times in twenty-five attempts, and the escaping read returned a resource
address from a file outside every root.

Answered by the guard opening the file and handing back the handle. The name
never leaves the package that approved it, so there is nothing left to
re-point — and the size and kind of the file are asked of the open handle for
the same reason.

The argument this file used to make about hard links does not cover this and
should not have been read as covering it: writing the plan gives an attacker
control of the plan, while this gave them a read over the whole filesystem.

### A hard link inside the project that points out of it

Not answered. A hard link has no path to resolve: the file simply has two names,
and the one inside the root is as real as the one outside. Nothing in the
filesystem API distinguishes it from an ordinary file.

The exposure is bounded by what a hard link can be made to: only a file on the
same device, and only by someone who could already write into the root. A
repository that an attacker can write into is a repository whose plan they can
write instead, which is a larger problem than this one. Recorded rather than
solved.

### A path that names one file and reads another

`root/link/../plan.json` cleaned lexically removes the climb and the link
together, so the path names one file and a different one is read. It lands
inside a root, so nothing escapes — but a report about a file the argument did
not name is an unstated fact matching another.

Answered by refusing a path that names a parent directory anywhere along it,
rather than cleaning it.

### A path chosen to exhaust the machine

`/dev/zero`, a named pipe, a sparse file of a terabyte. Reading it into memory
to parse it is what the verifier does with every plan.

Answered on the open file rather than on the path, because what a name referred
to a moment ago is not what it refers to now. Anything that is not a regular
file is refused, and the bound is on what is read rather than on a size reported
beforehand: sixty-four megabytes, refused rather than truncated, because half a
plan parses into a different change.

The open itself does not wait. A named pipe with no writer blocks on open,
before anything can look at what kind of file it is, so the check that refuses
it would never run.

### A request that never ends

A peer writing a gigabyte with no newline, or opening a message and stopping.

Answered by bounding one message at a megabyte and discarding the rest of an
oversized line rather than growing to hold it. The reader is told the message
was refused and answers it, so a client is never left waiting.

### A plan written to attack the reader of the report

The plan author controls resource addresses, `for_each` keys, and tag values,
and those reach the report. In a Markdown report they could open a heading, a
table row, a link, or an image; in a terminal they could move the cursor.

Answered in the renderer and the bundle contract, reviewed across milestones 01
to 04: no field carries a raw plan value into prose, evidence references carry a
location and never a value, control characters are collapsed everywhere, and
every structural character is escaped. The adapter returns the same bundle, so
it inherits all of it. What the adapter adds is that the *caller* is now a model,
which makes a forged instruction inside a plan value more attractive than a
forged heading — and the answer is the same, because the value never reaches the
output in a form that can carry either.

### A result that fills the caller's context

Everything a tool returns is read into a context window and repeated from
there. The loaders report one clause per offending entry, so a contract the
caller can write inside a root produced an error of the same order as the file
— ten megabytes of it, through a server whose inbound messages are bounded at
one.

Answered by bounding what a failed tool says back, and saying where it was cut.

### A sensitive value returned to a model

Terraform marks values sensitive so they are not printed. A model that reads one
may repeat it anywhere.

Answered by the bundle having nowhere to put one: an evidence reference locates
a value and cannot carry it, and a fact's state records that something was
withheld. Asserted from the adapter's side as well, over a plan whose policy is
marked sensitive.

### A tool result that instructs the model

Everything the adapter returns is either this build's own text or a value from
the bundle, and the bundle's free-text fields are written by this build. The
plan-derived parts are locations, not prose.

A reader should still treat a tool result as data. That is a property of the
client, not of this server, and this server cannot enforce it.

## What is deliberately not defended against

- **A hard link inside an allowed root**, as above.
- **A device file or a named pipe inside an allowed root.** The size check does
  not stop `/dev/zero` if it is linked into the root; the read is still bounded
  by the parser's own memory use, but not by the file's reported size.
- **Unbounded work inside the deadline.** One verification is abandoned after
  thirty seconds and the caller is told, which bounds what a caller waits for.
  It does not bound what the machine spends: there is nothing to cancel, because
  the work is a computation over values already in memory, so an abandoned
  verification runs to its end and holds its memory until it does. A caller
  that retried such a plan in a loop would accumulate them.
- **A malicious client.** The server trusts its own operator's choice of roots.
  A client that can start the server with `--root /` has already won, and no
  check inside the server can answer that.
- **Concurrency.** One request is served at a time, in the order they arrive.

## Residual risks, in one place

1. A hard link inside an allowed root reaches a file outside it.
2. An abandoned verification runs to its end and holds its memory until it does.
   Measured at roughly half a gigabyte for a plan near the size bound, and
   nothing caps how many may be in flight, so a caller that retries in a loop
   accumulates them.
3. A plan near the size bound needs more than the time bound allows, so the two
   limits are not consistent with each other: there are files this server will
   accept and never finish.
4. The roots are only as narrow as the operator made them.
