import sys
import os
import json


def main():
    # Output CGI headers if running in CGI mode
    if "GATEWAY_INTERFACE" in os.environ:
        print("Content-Type: application/json")
        print()  # Blank line ends headers

    # Read JSON input from stdin
    input_data = {}
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
            if raw.strip():
                input_data = json.loads(raw)
        except json.JSONDecodeError:
            pass

    name = input_data.get("name", "World")
    response = {"greeting": f"Hello, {name}!", "source": "example.pyz"}
    print(json.dumps(response))


if __name__ == "__main__":
    main()
