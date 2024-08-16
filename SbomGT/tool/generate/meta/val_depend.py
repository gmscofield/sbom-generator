import ast
import re
import os
import pandas as pd

P2I_FILE = os.path.join(os.path.dirname(__file__), "data", "p2i.csv")
p2idf = pd.read_csv(P2I_FILE)

def is_py_file(path):
    filename = os.path.basename(path)
    suffix = filename.split('.')[-1]
    if suffix == 'py':
        return True
    else:
        return False

def lib_extraction(line):
    t = '(^\s*import\s+([a-zA-Z0-9]*))|(^\s*from\s+([a-zA-Z0-9]*))'
    r = re.match(t, line)
    if r is not None:
        return r.groups()[1] if r.groups()[1] is not None else r.groups()[
            3]  # one of 1 and 3 will be None
    else:
        return None

def get_packages(import_name: str) -> set:
    return set(p2idf[p2idf['import']==import_name]['package'].values)

def get_imports(package_name: str) -> set:
    pkg = p2idf[p2idf['package']==package_name]['import'].values
    if pkg.size > 0:
        return pkg[0]
    else:
        return None

def parse_python_content(content: str) -> set:
    imports = set()
    try:
        t = ast.parse(content)
        for expr in ast.walk(t):
            if isinstance(expr, ast.ImportFrom):
                if expr.module is not None:
                    imports.add(expr.module.split('.')[0])
            elif isinstance(expr, ast.Import):
                for name in expr.names:
                    imports.add(name.name.split('.')[0])
    except Exception as e:
        for line in content.split('\n'):
            lib = lib_extraction(line)
            if lib is not None:
                imports.add(lib)
    packages = set()
    for import_name in imports:
        packages = packages.union(get_packages(import_name))
    
    pkg_import = []
    for pkg in packages:
        pkg_import.append({pkg: (None, get_imports(pkg))})
    return pkg_import

def parse_pyfile(filename):
    content = open(filename, 'r', errors='ignore').read()
    return parse_python_content(content)

if __name__ == "__main__":
    result = parse_pyfile("E:\\code\\sbom-project\\test\\test.py")
    print(result)