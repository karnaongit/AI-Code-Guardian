import sys
import os
import json
from pathlib import Path

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from github_api.file_service import SUPPORTED_EXTENSIONS

def main():
    workspace = Path(_PROJECT_ROOT)
    
    # We will ignore some common non-repo directories for counting
    ignore_dirs = {'.git', 'node_modules', '__pycache__', 'scratch', 'temp', '.cache', 'tmp_repo'}
    ignore_files = {'exec_output.txt'}
    
    total_files = 0
    extension_counts = {}
    ingested_files = 0
    excluded_extensions = {}
    
    all_files = []
    
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith('tmp_repo')]
        for file in files:
            if file in ignore_files: continue
            if file.endswith('.pyc') or file == '.oxlintrc.json':
                pass # skip these from repo source count if they aren't part of it
                
            path = Path(root) / file
            all_files.append(path)
            
            total_files += 1
            ext = path.suffix.lower()
            if not ext:
                ext = 'none'
                
            extension_counts[ext] = extension_counts.get(ext, 0) + 1
            
            if ext in SUPPORTED_EXTENSIONS:
                ingested_files += 1
            else:
                excluded_extensions[ext] = excluded_extensions.get(ext, 0) + 1
                
    print(f"TOTAL REPOSITORY FILES: {total_files}")
    print(f"SUPPORTED/INGESTED FILES: {ingested_files}")
    print(f"EXCLUDED FILES: {total_files - ingested_files}")
    
    print("\nEXTENSION BREAKDOWN:")
    for ext, count in sorted(extension_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ext.ljust(6)} = {count}")
        
    print("\nEXCLUDED EXTENSIONS:")
    for ext, count in sorted(excluded_extensions.items(), key=lambda x: x[1], reverse=True):
        print(f"{ext.ljust(6)} = {count}")
        
    print(f"\n.jsx EXCLUDED: {'YES' if '.jsx' not in SUPPORTED_EXTENSIONS else 'NO'}")
    print(f"SUPPORTED_EXTENSIONS: {SUPPORTED_EXTENSIONS}")

if __name__ == '__main__':
    main()
