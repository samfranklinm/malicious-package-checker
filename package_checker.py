# Package Comparison Tool
# Compare packages from package.json with malicious/suspicious packages 

import json
import pandas as pd
import sys
import requests
import urllib3
import ast
from io import StringIO
from typing import Dict, Set, Optional, Tuple, List

# Suppress SSL warnings for corporate environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def normalize_version(version: str) -> str:
    """Remove version prefixes like ^, ~, >=, etc."""
    if not version:
        return version
    # Remove common npm version prefixes
    for prefix in ['^', '~', '>=', '<=', '>', '<', '=']:
        if version.startswith(prefix):
            version = version[len(prefix):]
    return version.strip()

def version_matches(installed_version: str, vulnerable_versions: List[str]) -> bool:
    """Check if installed version matches any vulnerable version."""
    if not installed_version or not vulnerable_versions:
        return False
    
    # Normalize the installed version
    normalized_installed = normalize_version(installed_version)
    
    # Check against each vulnerable version
    for vuln_version in vulnerable_versions:
        normalized_vuln = normalize_version(vuln_version)
        if normalized_installed == normalized_vuln:
            return True
    
    return False

def load_package_json(file_path: str) -> Dict[str, str]:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        all_packages = {}
        
        # Check if this is a package-lock.json file
        if 'lockfileVersion' in data or 'packages' in data:
            print("Detected package-lock.json format")
            return load_package_lock(data)
        
        # Standard package.json format
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            if dep_type in data:
                all_packages.update(data[dep_type])
                
        return all_packages
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{file_path}': {e}")
        return {}

def load_package_lock(lock_data: Dict) -> Dict[str, str]:
    """Extract packages from package-lock.json format."""
    packages = {}
    
    # Handle different package-lock.json versions
    if 'packages' in lock_data:
        # npm v7+ format
        for package_path, package_info in lock_data['packages'].items():
            if package_path == '':  # Root package
                continue
            
            # Extract package name from path (remove node_modules prefix)
            package_name = package_path.replace('node_modules/', '')
            
            # Get version
            version = package_info.get('version', 'unknown')
            packages[package_name] = version
    
    elif 'dependencies' in lock_data:
        # npm v6 format
        def extract_from_dependencies(deps, prefix=''):
            for name, info in deps.items():
                version = info.get('version', 'unknown')
                full_name = f"{prefix}{name}" if prefix else name
                packages[full_name] = version
                
                # Recursively extract nested dependencies
                if 'dependencies' in info:
                    extract_from_dependencies(info['dependencies'], f"{full_name}/")
        
        extract_from_dependencies(lock_data['dependencies'])
    
    return packages

def load_csv_packages_from_url(url: str) -> Tuple[Dict[str, List[str]], pd.DataFrame]:
    try:
        print(f"Fetching malicious packages from: {url}")
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        
        packages_with_versions = {}
        for line in response.text.strip().split('\n'):
            line = line.strip()
            if line and ':' in line:
                parts = line.split(':', 1)
                package_name = parts[0].strip()
                if len(parts) > 1:
                    try:
                        # Parse the version list (Python literal eval)
                        versions_str = parts[1].strip()
                        versions = ast.literal_eval(versions_str)
                        if isinstance(versions, list):
                            packages_with_versions[package_name] = versions
                        else:
                            packages_with_versions[package_name] = [str(versions)]
                    except:
                        # If parsing fails, treat as single version
                        packages_with_versions[package_name] = [parts[1].strip()]
                else:
                    packages_with_versions[package_name] = []
        
        print(f"Loaded {len(packages_with_versions)} packages with versions from remote source")
        df = pd.DataFrame([{'package_name': k, 'versions': v} for k, v in packages_with_versions.items()])
        return packages_with_versions, df
    
    except requests.RequestException as e:
        print(f"Error fetching from URL: {e}")
        return {}, pd.DataFrame()
    except Exception as e:
        print(f"Error processing remote data: {e}")
        return {}, pd.DataFrame()

def load_csv_packages(csv_path: str, package_column: Optional[str] = None) -> Tuple[Dict[str, List[str]], pd.DataFrame]:
    try:
        packages_with_versions = {}
        
        with open(csv_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ':' in line:
                    parts = line.split(':', 1)
                    package_name = parts[0].strip()
                    if len(parts) > 1:
                        try:
                            # Parse the version list
                            versions_str = parts[1].strip()
                            versions = ast.literal_eval(versions_str)
                            if isinstance(versions, list):
                                packages_with_versions[package_name] = versions
                            else:
                                packages_with_versions[package_name] = [str(versions)]
                        except:
                            # If parsing fails, treat as single version
                            packages_with_versions[package_name] = [parts[1].strip()]
                    else:
                        packages_with_versions[package_name] = []
        
        print(f"Loaded {len(packages_with_versions)} packages with versions from {csv_path}")
        df = pd.DataFrame([{'package_name': k, 'versions': v} for k, v in packages_with_versions.items()])
        return packages_with_versions, df
    
    except FileNotFoundError:
        print(f"Error: File '{csv_path}' not found.")
        return {}, pd.DataFrame()
    except Exception as e:
        print(f"Error loading file: {e}")
        return {}, pd.DataFrame()

def compare_packages_with_csv(package_json_path: str, csv_source: str, 
                            package_column: Optional[str] = None,
                            case_sensitive: bool = True) -> Dict:
    json_packages = load_package_json(package_json_path)
    
    # Check if csv_source is a URL or file path
    if csv_source.startswith('http'):
        csv_packages_with_versions, csv_df = load_csv_packages_from_url(csv_source)
    else:
        csv_packages_with_versions, csv_df = load_csv_packages(csv_source, package_column)
    
    flagged_packages = {}
    clean_packages = set()
    
    # Check each package in the project
    for pkg_name, pkg_version in json_packages.items():
        is_flagged = False
        
        # Check against malicious packages (name matching)
        for malicious_pkg, vulnerable_versions in csv_packages_with_versions.items():
            if case_sensitive:
                name_match = pkg_name == malicious_pkg
            else:
                name_match = pkg_name.lower() == malicious_pkg.lower()
            
            if name_match:
                # Check if installed version matches any vulnerable version
                if version_matches(pkg_version, vulnerable_versions):
                    flagged_packages[pkg_name] = {
                        'installed_version': pkg_version,
                        'vulnerable_versions': vulnerable_versions
                    }
                    is_flagged = True
                    break
        
        if not is_flagged:
            clean_packages.add(pkg_name)
    
    return {
        'total_packages': len(json_packages),
        'flagged_packages': flagged_packages,
        'clean_packages': clean_packages,
        'flagged_count': len(flagged_packages),
        'clean_count': len(clean_packages),
        'package_versions': json_packages
    }

def print_comparison_report(results: Dict):
    print("="*50)
    print("PACKAGE SECURITY CHECK REPORT")
    print("="*50)
    
    print(f"Total packages: {results['total_packages']}")
    print(f"Flagged: {results['flagged_count']}")
    print(f"Clean: {results['clean_count']}")
    
    if results['flagged_count'] > 0:
        print(f"\n⚠️  WARNING: {results['flagged_count']} flagged packages!")
        print("\nFlagged packages:")
        for pkg_name, details in sorted(results['flagged_packages'].items()):
            installed_version = details['installed_version']
            vulnerable_versions = details['vulnerable_versions']
            print(f"  • {pkg_name}")
            print(f"    Installed: {installed_version}")
            print(f"    Vulnerable: {', '.join(vulnerable_versions)}")
    else:
        print("\n✅ No flagged packages found")
    
    if results['clean_packages'] and len(results['clean_packages']) <= 10:
        print(f"\nClean packages:")
        for pkg in sorted(results['clean_packages']):
            version = results['package_versions'].get(pkg, 'N/A')
            print(f"  • {pkg} ({version})")
    elif results['clean_packages']:
        for pkg in sorted(list(results['clean_packages'])):
            version = results['package_versions'].get(pkg, 'N/A')
            print(f"  • {pkg} ({version})")

if __name__ == "__main__":
    print("Package Security Checker\n========================\n")
    
    # Default GitHub Gist URL for malicious packages
    default_url = "https://gist.githubusercontent.com/cx-tal-folkman/d507b095048b7ad02badfe9a99fe4002/raw/malicious_packages.csv"
    
    if len(sys.argv) == 2:
        # Only package file provided, use default URL
        package_file_path = sys.argv[1]
        csv_source = default_url
        print("Using default malicious packages database from GitHub")
    elif len(sys.argv) == 3:
        # Both package file and csv source provided
        package_file_path = sys.argv[1]
        csv_source = sys.argv[2]
    else:
        print("Usage:")
        print("  python script.py <package.json|package-lock.json path>")
        print("  python script.py <package.json|package-lock.json path> <csv_path_or_url>")
        print("\nExamples:")
        print("  python script.py package.json")
        print("  python script.py package-lock.json")
        print("  python script.py package.json malicious_packages.csv")
        print("  python script.py package-lock.json https://example.com/malicious.csv")
        sys.exit(1)
    
    try:
        results = compare_packages_with_csv(package_file_path, csv_source, case_sensitive=False)
        print_comparison_report(results)
        
        if results['flagged_count'] > 0:
            print(f"\n🚨 SECURITY ALERT: {results['flagged_count']} flagged packages found!")
        else:
            print(f"\n✅ SECURITY CHECK PASSED")
        
    except Exception as e:
        print(f"Error: {e}")
        print("Check file paths and network connection")