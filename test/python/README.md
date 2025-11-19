# Python on os402

Run Python applications in a diskless sandbox with resource limits, network controls, and cryptographic attestation.

## How it Works

os402 uses [Cosmopolitan Python](https://cosmo.zip/) - a single portable binary with the entire Python stdlib embedded. This means:

- **No filesystem required** - Python runs entirely from memory
- **Single executable** - All Python apps share the same ~30MB runtime
- **Cross-platform** - Same binary works on Linux, macOS, Windows, BSD

The clever part is how we load Python applications: the app is packaged as a [zipapp](https://docs.python.org/3/library/zipapp.html) (.pyz file) and sent over stdin using a simple protocol:

```
<size_in_bytes>\n<zipapp_bytes><optional_cgi_body>
```

A tiny bootstrap snippet reads this and executes the zipapp in-memory:

```python
import sys,io,zipfile
raw = sys.stdin.buffer.read()
nl = raw.find(b'\n')
sz = int(raw[:nl])
zb = raw[nl+1:nl+1+sz]
sys.stdin = io.TextIOWrapper(io.BytesIO(raw[nl+1+sz:]))  # remaining bytes become new stdin
exec(compile(zipfile.ZipFile(io.BytesIO(zb)).read("__main__.py"), "<zipapp>", "exec"))
```

## Quick Start

### 1. Create Your App

Structure your app with a `__main__.py`:

```
my-app/
  __main__.py
  helper.py  # optional additional modules
```

Example `__main__.py` for a CGI endpoint:

```python
import sys
import os
import json

def main():
    # Output CGI headers
    print("Content-Type: application/json")
    print()  # blank line ends headers

    # Read JSON from request body
    input_data = json.loads(sys.stdin.read() or "{}")

    # Your logic here
    result = {"message": f"Hello, {input_data.get('name', 'World')}!"}
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

### 2. Package as Zipapp

```bash
python -m zipapp my-app -o my-app.pyz
```

### 3. Create the Offer

```bash
# Prepare stdin: size prefix + zipapp bytes
(wc -c < my-app.pyz | tr -d ' '; cat my-app.pyz) > my-app-stdin.bin

# Create and upload offer
os402 offer \
    --name my-python-app \
    --exe runtime/cosmo-python \
    -e COSMOPOLITAN_INIT_ZIPOS=/proc/self/exe \
    --cpu-units 1000 \
    --ram-mb 256 \
    --price-per-second 0.0001 \
    --min-duration 5 \
    --cgi \
    --stdin @my-app-stdin.bin \
    --stdin-private \
    --upload https://your-server.com \
    -- python -c 'import sys,io,zipfile;raw=sys.stdin.buffer.read();nl=raw.find(b"\n");sz=int(raw[:nl]);zb=raw[nl+1:nl+1+sz];sys.stdin=io.TextIOWrapper(io.BytesIO(raw[nl+1+sz:]));exec(compile(zipfile.ZipFile(io.BytesIO(zb)).read("__main__.py"),"<zipapp>","exec"))' \
    > my-offer.json
```

### 4. Call Your Endpoint

```bash
HASH=$(jq -r .sha256 my-offer.json)
os402 curl -X POST -d '{"name": "Alice"}' https://your-server.com/$HASH.cgi
```

## Testing

```bash
# Setup runtime (downloads Cosmopolitan Python)
make setup-runtime

# Run all tests (requires os402 server running)
make test

# Just launcher tests (no server needed)
make test-launcher
```

## Files

- `apploader/` - Full-featured launcher with import hook support
- `example/` - Simple test application
- `runtime/` - Downloaded Python runtime (gitignored)
- `Makefile` - Build and test automation

## Why Cosmopolitan Python?

The os402 sandbox is diskless - there's no filesystem to read Python's stdlib from. Cosmopolitan Python solves this by embedding the entire stdlib inside the binary itself, accessed via a virtual filesystem (`/zip/...`). This is the only way to run Python in a fully isolated, memory-only sandbox that forms our baseline compatibility requirement.

This means your Python code runs with all the os402 guarantees:
- CPU and memory limits enforced by the kernel
- Optional network isolation
- Deterministic caching
- Signed attestations of execution

Other Python distributions (python-build-standalone, system Python, etc.) require filesystem access to their stdlib directories and won't work.

