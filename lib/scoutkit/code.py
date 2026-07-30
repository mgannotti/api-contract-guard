"""Code-domain primitives shared by every analyzer in the pack.

Walking a repository, naming what a file *is*, and reading an exported git
history. Nothing here shells out to git, clones anything, or reaches the
network — a history is supplied as a text export the caller generated, which
keeps every skill in the pack runnable against evidence rather than a live
working copy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .io import EvidenceError

__all__ = [
    "Commit",
    "FileChange",
    "IGNORED_DIRS",
    "LANGUAGE_BY_SUFFIX",
    "classify_path",
    "detect_language",
    "is_probably_binary",
    "iter_repo_files",
    "parse_git_log",
    "parse_iso_date",
    "repo_relative",
]

# Directories that are never the subject of analysis: dependency trees, build
# output, and virtual environments. Walking them makes every measurement wrong —
# a repo's "hot spots" become whatever npm installed most recently.
IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", ".vs",
    "node_modules", "bower_components", "jspm_packages",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
    "venv", ".venv", "env", ".env.d", "virtualenv",
    "dist", "build", "out", "target", "bin", "obj", ".next", ".nuxt", ".output",
    "vendor", "third_party", "thirdparty", "external",
    "coverage", "htmlcov", ".coverage", ".nyc_output",
    ".terraform", ".gradle", ".m2", "Pods", "DerivedData",
})

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".groovy": "Groovy",
    ".cs": "C#", ".fs": "F#", ".vb": "Visual Basic",
    ".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
    ".m": "Objective-C", ".mm": "Objective-C", ".swift": "Swift",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
    ".sql": "SQL", ".r": "R", ".jl": "Julia", ".lua": "Lua", ".dart": "Dart", ".ex": "Elixir",
    ".exs": "Elixir", ".erl": "Erlang", ".clj": "Clojure", ".hs": "Haskell",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "CSS", ".sass": "CSS", ".less": "CSS",
    ".vue": "Vue", ".svelte": "Svelte",
    ".json": "Data", ".yaml": "Data", ".yml": "Data", ".toml": "Data", ".xml": "Data",
    ".ini": "Data", ".cfg": "Data", ".csv": "Data",
    ".md": "Docs", ".markdown": "Docs", ".rst": "Docs", ".adoc": "Docs", ".txt": "Docs",
}

# Suffixes worth reading as source even though they carry no extension language.
_SOURCE_KINDS = frozenset({
    "Python", "JavaScript", "TypeScript", "Go", "Rust", "Ruby", "PHP", "Java",
    "Kotlin", "Scala", "Groovy", "C#", "F#", "Visual Basic", "C", "C++",
    "Objective-C", "Swift", "Shell", "PowerShell", "SQL", "R", "Julia", "Lua",
    "Dart", "Elixir", "Erlang", "Clojure", "Haskell", "Vue", "Svelte",
    "HTML", "CSS",
})

_TEST_DIR = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testing|e2e|integration[-_]tests?)(/|$)", re.I)
_TEST_FILE = re.compile(r"(^|/)(test_[^/]+|[^/]+_test|[^/]+\.test|[^/]+\.spec|Test[A-Z][^/]*)\.[^/.]+$")
_DOC_DIR = re.compile(r"(^|/)(docs?|documentation|examples?|samples?)(/|$)", re.I)
_CI_DIR = re.compile(r"(^|/)(\.github|\.gitlab|\.circleci|\.azure(-|_)?pipelines|ci|\.ci)(/|$)", re.I)

_CONFIG_NAMES = frozenset({
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock",
    "pipfile", "pipfile.lock", "setup.py", "setup.cfg", "tox.ini",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock",
    "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "makefile",
    ".gitignore", ".editorconfig", ".env", ".env.example", "pytest.ini",
})

_BINARY_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".pdf",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".jar", ".war", ".exe", ".dll", ".so",
    ".dylib", ".pyc", ".pyo", ".class", ".o", ".a", ".lib", ".bin", ".dat",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".mov", ".avi",
    ".xlsx", ".docx", ".pptx", ".sqlite", ".db",
})


def detect_language(path: str | Path) -> str:
    """Language name for a path, or ``"Other"`` when the suffix is unknown."""
    name = Path(path).name.lower()
    if name in {"dockerfile", "makefile", "rakefile", "gemfile", "vagrantfile"}:
        return name.capitalize()
    return LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower(), "Other")


def is_source(path: str | Path) -> bool:
    return detect_language(path) in _SOURCE_KINDS


def is_probably_binary(path: str | Path) -> bool:
    return Path(path).suffix.lower() in _BINARY_SUFFIXES


def classify_path(rel: str) -> str:
    """Name the role a path plays: test, docs, ci, config, source, or asset.

    Order matters. A file under ``tests/`` that happens to be named
    ``config.py`` is test scaffolding, not configuration, and counting it as
    configuration is how coverage tools end up reporting that the test
    directory is undertested.
    """
    posix = str(rel).replace("\\", "/")
    if posix.startswith("./"):
        posix = posix[2:]
    name = posix.rsplit("/", 1)[-1].lower()

    if _TEST_DIR.search(posix) or _TEST_FILE.search(posix):
        return "test"
    if _CI_DIR.search(posix):
        return "ci"
    if _DOC_DIR.search(posix) or detect_language(posix) == "Docs":
        return "docs"
    if name in _CONFIG_NAMES or name.startswith(".env"):
        return "config"
    if is_probably_binary(posix):
        return "asset"
    if is_source(posix):
        return "source"
    if detect_language(posix) == "Data":
        return "config"
    return "other"


def repo_relative(path: Path, root: Path) -> str:
    """Forward-slashed path relative to the repo root, stable across platforms."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return path.name


def iter_repo_files(
    root: str | Path,
    *,
    include_ignored_dirs: bool = False,
    max_files: int = 20000,
) -> Iterator[Path]:
    """Yield files under ``root`` in sorted order, skipping dependency trees.

    Sorted so that two runs over an unchanged tree produce identical reports.
    ``max_files`` is a guard, not a preference: crossing it means the caller is
    pointed at something larger than a repository and the result would be
    misleading rather than merely slow.
    """
    base = Path(root)
    if base.is_file():
        yield base
        return
    if not base.is_dir():
        raise EvidenceError(f"no such directory: {base}")

    count = 0
    stack = [base]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except (PermissionError, OSError):
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if include_ignored_dirs or entry.name not in IGNORED_DIRS:
                        stack.append(entry)
                elif entry.is_file():
                    count += 1
                    if count > max_files:
                        raise EvidenceError(
                            f"more than {max_files} files under {base}; point this at a "
                            f"repository rather than a parent directory"
                        )
                    yield entry
            except OSError:
                continue


def parse_iso_date(value: Any) -> date | None:
    """Parse an ISO-ish date from a string, dict, or timestamp. None when unusable."""
    if isinstance(value, dict):
        value = value.get("dateTime") or value.get("date") or value.get("value")
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).date()
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d %b %Y", "%a %b %d %H:%M:%S %Y %z"):
            try:
                parsed = datetime.strptime(text[:len(text)], fmt)
                break
            except ValueError:
                continue
        else:
            try:
                return datetime.strptime(text[:10], "%Y-%m-%d").date()
            except ValueError:
                return None
    return parsed.astimezone(timezone.utc).date() if parsed.tzinfo else parsed.date()


@dataclass(frozen=True, slots=True)
class FileChange:
    """One file touched by one commit."""

    path: str
    added: int = 0
    removed: int = 0
    binary: bool = False

    @property
    def churn(self) -> int:
        return self.added + self.removed


@dataclass
class Commit:
    """One commit from an exported history."""

    sha: str = ""
    author: str = ""
    email: str = ""
    when: date | None = None
    subject: str = ""
    body: str = ""
    files: list[FileChange] = field(default_factory=list)

    @property
    def churn(self) -> int:
        return sum(f.churn for f in self.files)

    def to_dict(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "churn": self.churn,
            "date": self.when.isoformat() if self.when else None,
            "files": [
                {"added": f.added, "path": f.path, "removed": f.removed, "binary": f.binary}
                for f in self.files
            ],
            "sha": self.sha,
            "subject": self.subject,
        }


# A history export is produced by the caller with a documented command:
#
#     git log --numstat --date=short --pretty=format:"%H%x09%an%x09%ae%x09%ad%x09%s"
#
# Each commit is that header line followed by numstat rows. Both the tab-
# delimited header and a looser "commit <sha>" form are accepted, because the
# second is what people paste when they ran plain `git log --numstat`.
_HEADER_TAB = re.compile(
    r"^(?P<sha>[0-9a-f]{7,40})\t(?P<author>[^\t]*)\t(?P<email>[^\t]*)\t(?P<date>[^\t]*)\t(?P<subject>.*)$"
)
_HEADER_COMMIT = re.compile(r"^commit\s+(?P<sha>[0-9a-f]{7,40})")
_NUMSTAT = re.compile(r"^(?P<added>\d+|-)\t(?P<removed>\d+|-)\t(?P<path>.+)$")
_AUTHOR_LINE = re.compile(r"^Author:\s*(?P<author>.*?)\s*(?:<(?P<email>[^>]*)>)?\s*$")
_DATE_LINE = re.compile(r"^Date:\s*(?P<date>.+?)\s*$")
# git renames arrive as "old/{a => b}/new" or "old => new"; the post-rename path
# is the one that exists now, so that is the one worth attributing churn to.
_RENAME_BRACE = re.compile(r"^(?P<prefix>.*)\{(?P<old>[^}]*?)\s*=>\s*(?P<new>[^}]*?)\}(?P<suffix>.*)$")
_RENAME_PLAIN = re.compile(r"^(?P<old>.+?)\s*=>\s*(?P<new>.+)$")


def _resolve_rename(path: str) -> str:
    brace = _RENAME_BRACE.match(path)
    if brace:
        joined = f"{brace['prefix']}{brace['new']}{brace['suffix']}"
        return re.sub(r"//+", "/", joined).strip()
    plain = _RENAME_PLAIN.match(path)
    if plain:
        return plain["new"].strip()
    return path.strip()


def parse_git_log(text: str) -> list[Commit]:
    """Parse a ``git log --numstat`` export into commits.

    Tolerant by design: a history someone pasted is usually missing something.
    A commit with a header and no numstat rows is kept with an empty file list
    rather than dropped, because "this commit touched nothing we can see" is
    different from "this commit did not happen".
    """
    if not text or not text.strip():
        raise EvidenceError("the history export is empty")

    commits: list[Commit] = []
    current: Commit | None = None
    pending_subject = False

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()

        tab = _HEADER_TAB.match(line)
        if tab:
            current = Commit(
                sha=tab["sha"], author=tab["author"].strip(), email=tab["email"].strip(),
                when=parse_iso_date(tab["date"]), subject=tab["subject"].strip(),
            )
            commits.append(current)
            pending_subject = False
            continue

        head = _HEADER_COMMIT.match(line)
        if head:
            current = Commit(sha=head["sha"])
            commits.append(current)
            pending_subject = False
            continue

        if current is None:
            continue

        author = _AUTHOR_LINE.match(line)
        if author and not current.author:
            current.author = (author["author"] or "").strip()
            current.email = (author["email"] or "").strip()
            continue

        when = _DATE_LINE.match(line)
        if when and current.when is None:
            current.when = parse_iso_date(when["date"])
            pending_subject = True
            continue

        stat = _NUMSTAT.match(line)
        if stat:
            binary = stat["added"] == "-" or stat["removed"] == "-"
            current.files.append(FileChange(
                path=_resolve_rename(stat["path"]),
                added=0 if binary else int(stat["added"]),
                removed=0 if binary else int(stat["removed"]),
                binary=binary,
            ))
            pending_subject = False
            continue

        if pending_subject and stripped:
            current.subject = stripped
            pending_subject = False

    if not commits:
        raise EvidenceError(
            "no commits found. Export a history with: git log --numstat --date=short "
            '--pretty=format:"%H%x09%an%x09%ae%x09%ad%x09%s"'
        )
    return commits
