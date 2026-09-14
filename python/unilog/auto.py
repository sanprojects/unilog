"""The one-line entrypoint: `import unilog.auto`. Side effect only — installs
the root logging handler and all crash hooks immediately on import."""

from __future__ import annotations

from . import _install

_install.install()
