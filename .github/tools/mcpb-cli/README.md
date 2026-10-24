# MCPB release tool

Install the locked dependencies with `npm ci --ignore-scripts`, then run
`node harden-forge.cjs` and `node harden-zod.cjs` before invoking the MCPB CLI.
The MCPB workflows enforce this order. The tool is a build dependency and is
not included in Guard packages.

The locked Forge 1.4.0 has an incomplete RSA DigestInfo validation fix
([upstream report](https://github.com/digitalbazaar/forge/issues/1149)).
The local backport accepts only an OID followed by an optional primitive, empty
NULL in the AlgorithmIdentifier. It rejects extra elements and malformed NULLs.
It verifies the complete original `rsa.js` SHA-256 before patching, rejects
unrecognized source or versions, and supports idempotent invocation.

Each invocation tests canonical RSA signatures, an incorrect digest, and three
malformed AlgorithmIdentifiers. `verify-forge.cjs` fails on the original package.
Only a successful backport and regression check can generate the OpenVEX record.
The security workflow applies that record solely to the MCPB tool directory;
the rest of the repository is scanned separately without it. Other advisories
remain blocking. The lock retains the upstream version, so registry-only audits
cannot infer that the local source has been patched. Each OpenVEX statement
names this tool directory as its product and the registry package as a
subcomponent of it, so a scanner cannot read the `fixed` status as a claim
about any other install of that version.

Remove the backport after a corrected upstream release is pinned and the same
negative verification cases pass against it. A version change fails the current
backport gate and requires explicit review.

The locked zod 3.25.76 is the classic parser `@anthropic-ai/mcpb` 2.1.2 imports.
No newer MCPB release exists, and its schemas are unbounded `z.array()` calls.
Zod 4.6.6 stops an oversized array only when the schema already has an upper
bound, and its `zod/v3` entry is still this classic parser. No zod 3 release
contains the bound check. `harden-zod.cjs` verifies the published `v3/types.js`
and `v3/types.cjs` SHA-256 values, then applies two changes: `.max()`,
`.length()`, and `.size()` return before any element is parsed, and a failing
array or set stops after 32 issues. A successful parse is unchanged. The lock
keeps 3.25.76, so a registry audit still reports the advisory.
