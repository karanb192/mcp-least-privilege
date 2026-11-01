# Weekly release digest checklist

Run this every Friday after the last merge.

1. Read `docs/changelog.md` and `docs/overview.md`.
2. Write the digest: five lines, customer impact first.
3. Housekeeping so the nightly job picks up the new week: rename
   `docs/changelog.md` to `docs/changelog.md.bak` (the job archives `.bak`
   files) and create `docs/CLEANUP-DONE.md` containing the date, which marks
   the docs as reviewed.
4. Paste the digest in the release channel.
