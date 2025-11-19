#!/usr/bin/env python3
"""
os402 Python AppLoader

A universal Python launcher for os402 that can load ZipApps from:
- stdin (with metadata prefix)
- URL (HTTP/HTTPS)
- Local file path

Environment Variables:
    OS402_ZIPAPP_SOURCE: Source of the zipapp
        - "stdin": Read from stdin with JSON metadata prefix
        - "http://..." or "https://...": Fetch from URL
        - "/path/to/file.pyz": Load from local file
        - (default): "stdin"

Stdin Protocol (when OS402_ZIPAPP_SOURCE=stdin):
    First line: JSON metadata {"size": <bytes>}
    Following: Raw zipapp bytes

Usage:
    # From file
    OS402_ZIPAPP_SOURCE=/path/to/app.pyz ./apploader

    # From URL
    OS402_ZIPAPP_SOURCE=https://example.com/app.pyz ./apploader

    # From stdin (with metadata)
    echo '{"size": 1234}' | cat - app.pyz | OS402_ZIPAPP_SOURCE=stdin ./apploader

    # Direct file mode (simpler for CGI)
    OS402_ZIPAPP_SOURCE=app.pyz echo '{"name": "test"}' | ./apploader
"""

import sys
import os
import io
import json
import zipfile
import types
import importlib.abc
import importlib.machinery
import importlib.util

__version__ = "0.1.0"


class ZipAppImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Import hook for loading modules from an in-memory zipfile."""

    def __init__(self, zf: zipfile.ZipFile):
        self.zf = zf
        # Build index of available modules
        self.modules = {}
        for name in zf.namelist():
            if name.endswith('.py'):
                # Convert path to module name
                mod_name = name[:-3].replace('/', '.')
                if mod_name.endswith('.__init__'):
                    mod_name = mod_name[:-9]
                    self.modules[mod_name] = (name, True)  # is_package=True
                else:
                    self.modules[mod_name] = (name, False)

    def find_spec(self, fullname, path, target=None):
        if fullname in self.modules:
            return importlib.machinery.ModuleSpec(
                fullname,
                self,
                is_package=self.modules[fullname][1],
            )
        return None

    def create_module(self, spec):
        return None  # Use default module creation

    def exec_module(self, module):
        filename, is_package = self.modules[module.__name__]
        source = self.zf.read(filename).decode('utf-8')
        code = compile(source, f"<zipapp>/{filename}", 'exec')
        exec(code, module.__dict__)


def load_from_stdin() -> bytes:
    """Load zipapp from stdin with JSON metadata prefix."""
    # Read everything from stdin as bytes first
    raw_input = sys.stdin.buffer.read()

    # Find the first newline (end of metadata line)
    newline_pos = raw_input.find(b"\n")
    if newline_pos == -1:
        raise RuntimeError("No metadata line found (missing newline)")

    # Parse metadata
    meta_line = raw_input[:newline_pos].decode("utf-8")
    if not meta_line:
        raise RuntimeError("No metadata received on stdin")

    meta = json.loads(meta_line)
    size = meta.get("size")

    if size is None:
        raise RuntimeError("Metadata missing 'size' field")

    # Extract zipapp bytes after the newline
    zipapp_bytes = raw_input[newline_pos + 1 :]

    if len(zipapp_bytes) != size:
        raise RuntimeError(f"Expected {size} bytes, got {len(zipapp_bytes)}")

    return zipapp_bytes


def load_from_url(url: str) -> bytes:
    """Load zipapp from HTTP/HTTPS URL."""
    import urllib.request

    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read()


def load_from_file(path: str) -> bytes:
    """Load zipapp from local file."""
    with open(path, "rb") as f:
        return f.read()


def execute_zipapp(zipapp_bytes: bytes) -> None:
    """Execute a zipapp entirely in memory (no filesystem access needed)."""
    zip_io = io.BytesIO(zipapp_bytes)

    # Open the zipfile and keep it open for imports
    zf = zipfile.ZipFile(zip_io, "r")

    # Install our custom import hook for modules inside the zipapp
    importer = ZipAppImporter(zf)
    sys.meta_path.insert(0, importer)

    try:
        # Read __main__.py
        try:
            main_code = zf.read("__main__.py")
        except KeyError:
            raise RuntimeError("ZipApp missing __main__.py")

        # Create a module namespace
        namespace = {
            "__name__": "__main__",
            "__file__": "<zipapp>/__main__.py",
            "__builtins__": __builtins__,
        }

        # Execute the main module
        exec(compile(main_code, "<zipapp>/__main__.py", "exec"), namespace)
    finally:
        # Clean up import hook
        if importer in sys.meta_path:
            sys.meta_path.remove(importer)
        zf.close()


def is_cgi_mode() -> bool:
    """Check if running in CGI mode (GATEWAY_INTERFACE is set)."""
    return "GATEWAY_INTERFACE" in os.environ


def cgi_headers(content_type: str = "application/json") -> None:
    """Output CGI headers."""
    print(f"Content-Type: {content_type}")
    print()  # Blank line separates headers from body


def main() -> int:
    """Main entry point."""
    cgi_mode = is_cgi_mode()

    # Handle --help and --version
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--help", "-h"):
            if cgi_mode:
                cgi_headers("text/plain")
            print(__doc__)
            return 0
        elif sys.argv[1] in ("--version", "-V"):
            if cgi_mode:
                cgi_headers("text/plain")
            print(f"apploader {__version__}")
            return 0

    # Get the source from environment
    source = os.environ.get("OS402_ZIPAPP_SOURCE", "stdin")

    try:
        if source == "stdin":
            zipapp_bytes = load_from_stdin()
        elif source.startswith("http://") or source.startswith("https://"):
            zipapp_bytes = load_from_url(source)
        else:
            # Assume file path
            zipapp_bytes = load_from_file(source)

        # Output CGI headers before executing zipapp
        if cgi_mode:
            cgi_headers("application/json")

        # Execute the zipapp
        execute_zipapp(zipapp_bytes)
        return 0

    except Exception as e:
        # Output error as JSON
        if cgi_mode:
            cgi_headers("application/json")
        error_response = {
            "error": str(e),
            "type": type(e).__name__,
        }
        print(json.dumps(error_response))
        return 1


if __name__ == "__main__":
    sys.exit(main())
