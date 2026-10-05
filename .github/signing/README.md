# Release signing policy

The prospective signing checkpoint is Oshioki **v0.4.1**. New commits and
annotated release tags use cryptographic signatures; existing history and
older unsigned tags remain unchanged.

Eric Psalmond's release signer is pinned in `allowed_signers`:

- Principal: `epsalmond@gmail.com`
- SSH ED25519 fingerprint: `SHA256:TzhZQs7IkRk41Y1UxiNVZfLRJBO8MMAte5YEhQHmfdw`
- Namespace: `git`

The key is public only. Its private half stays on the maintainer's signing
host and is never supplied to Actions. GitHub web-flow signatures on reviewed
merge commits are separate from the release tag signer.

Approve this fingerprint independently before merging the checkpoint. The
release verifier uses the committed policy from fetched `origin/main`, not a
key supplied by the tag or an environment-selected trust file. This trusts
the canonical repository's reviewed main branch and its governance; a
signed tag carrying its own key would not establish first trust. Record the
merged checkpoint SHA and signed tag-object SHA with release evidence.

Rotation and emergency recovery are in [the release guide](../../docs/releases.md).
