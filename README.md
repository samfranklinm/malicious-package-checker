# Package Security Checker

In response to the recent Shai-Hulud attack. I created this simple, lightweight Python script that scans npm packages against a database of known malicious packages.

## Installation

```bash
pip install requests pandas urllib3
```

## Usage

```bash
# Use default GitHub database
python "Package Comparison Tool.py" package.json

# Use custom CSV file
python "Package Comparison Tool.py" package.json malicious_packages.csv
```

## Supported Files

- `package.json`
- `package-lock.json`

## Output

- ✅ **Clean**: No malicious packages found
- 🚨 **Alert**: Shows flagged packages with versions

## How It Works

1. Loads your packages and versions
2. Fetches malicious packages list from [cx-tal-folkman/malicious_packages.csv](https://gist.github.com/cx-tal-folkman/d507b095048b7ad02badfe9a99fe4002)
3. Compares package names and versions
4. Reports any matches

## Example

```bash
$ python "Package Comparison Tool.py" package.json

Package Security Checker
========================
Total packages: 56
Flagged: 0
Clean: 56

✅ SECURITY CHECK
