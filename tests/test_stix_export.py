"""
AegisNIDS Root Test Suite Wrapper: STIX 2.1 Export Validation Tests
Redirects to src/flask-api/test_stix_export.py
"""
import os
import subprocess
import sys

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(root_dir, "src", "flask-api")
    script = os.path.join(target_dir, "test_stix_export.py")
    python_bin = sys.executable
    venv_py = os.path.join(target_dir, ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_py):
        python_bin = venv_py
    res = subprocess.run([python_bin, script], cwd=target_dir)
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
