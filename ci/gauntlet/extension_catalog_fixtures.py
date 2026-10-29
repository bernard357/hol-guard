"""A committed extension catalog entry whose name carries a credential word.

``contributions/extensions/command.kubernetes-secrets.json`` describes a
command that lists cluster secrets; it holds no secret itself. The credential
name screens used to hold every read and in-place edit of it for review,
even inside the session's own repository. Every value here is synthetic.

* ``SOURCES`` are committed in the main checkout, so the linked worktree an
  agent starts in has them tracked too.
"""

from __future__ import annotations

CONTRIBUTIONS = "contributions"
CATALOG_PATH = f"{CONTRIBUTIONS}/extensions/command.kubernetes-secrets.json"
CATALOG_SOURCE = (
    '{\n  "id": "command.kubernetes-secrets",\n  "title": "List cluster secrets",\n  "version": "1.0.0"\n}\n'
)

SOURCES = {CATALOG_PATH: CATALOG_SOURCE}
