import os
import ast
import pandas as pd
import re
from uuid import uuid4
import pkg_resources
import logging
import sys
from packageurl import PackageURL
from packageurl.contrib import url2purl
from typing import Optional, List
from ....output import middleware
from ....schema.cdx_model import spdx


ALGOLIST = [
    "SHA1", 
    "SHA224", 
    "SHA256", 
    "SHA384", 
    "SHA512", 
    "SHA3-256", 
    "SHA3-384", 
    "SHA3-512", 
    "BLAKE2b-256", 
    "BLAKE2b-384", 
    "BLAKE2b-512", 
    "BLAKE3", 
    "MD2", 
    "MD4", 
    "MD5", 
    "MD6", 
    "ADLER32"
]

P2I_FILE = os.path.join(os.path.dirname(__file__), "data", "p2i.csv")

p2idf = pd.read_csv(P2I_FILE)


def component_meta_template() -> dict:
    return {
        "component": None, 
        "dependson": {}, 
        "relationships": {},
        "others": {}
    }


def str2license(license_str: Optional[str]) -> Optional[List[middleware.License]]:
    if not license_str:
        return None
    if license_str in [member.value for member in spdx.Schema]:
        pkg_license = middleware.License(type='concluded', spdxID=license_str)
    else:
        pkg_license = middleware.License(type='concluded', name=license_str)
    return [pkg_license]


def name_email_str2ind(name: Optional[str], email: Optional[str]) -> Optional[middleware.Individual]:
    if name or email:
        if email == None and "(" in name:
            name, email = name.split("(")
            email = email.rstrip(")").strip()
        return middleware.Individual(
            type="organization" if "Inc" in name or "inc" in name else "person",
            name=name,
            email=email
        )
    else:
        return None


def parse_depend(depend: str) -> dict:
    depend = depend.replace(" ", "")
    for i in range(len(depend)):
        if depend[i] in ('<', '>', '=', '!', '~', '^', '*', '(', ')', ':'):
            return {depend[:i]: (depend[i:], get_imports(depend[:i]))}            
    return {depend: (None, get_imports(depend))}


def normalize_pkgname(package_name: str) -> str:
    return re.sub('[^A-Za-z0-9.]+', '-', package_name)


def is_valid_purl(purl: str) -> bool:
    purl_regex = re.compile(
        r'^pkg:(?P<type>[^/]+)/(?:(?P<namespace>[^/]+)/)?(?P<name>[^@]+)(?:@(?P<version>[^?]+))?(?:\?(?P<qualifiers>[^#]+))?(?:#(?P<subpath>.*))?$'
    )
    match = purl_regex.match(purl)
    return match is not None


def is_py_file(path: str) -> bool:
    filename = os.path.basename(path)
    suffix = filename.split('.')[-1]
    if suffix == 'py':
        return True
    else:
        return False


def lib_extraction(line: str) -> Optional[str]:
    t = '(^\s*import\s+([a-zA-Z0-9]*))|(^\s*from\s+([a-zA-Z0-9]*))'
    r = re.match(t, line)
    if r is not None:
        return r.groups()[1] if r.groups()[1] is not None else r.groups()[3]  # one of 1 and 3 will be None
    else:
        return None


def get_packages(import_name: str) -> set:
    pkgs = set(p2idf[p2idf['import']==import_name]['package'].values)
    if len(pkgs) > 0:
        return pkgs
    else:
        return None


def get_imports(package_name: str) -> set:
    imports = set(p2idf[p2idf['package']==package_name]['import'].values)
    if len(imports) > 0:
        return imports
    else:
        return None


def pyfile_depends_else(filename: str) -> List[str]:
    content = open(filename, 'r', errors='ignore').read()
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
    
    return list(imports)


class ImportAnalyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.all_imports = []
        self.conditional_imports = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top_name = alias.name.split('.')[0]
            self.all_imports.append((top_name, node.lineno))
            if self.is_in_conditional(node):
                self.conditional_imports.append((top_name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module.split('.')[0] if node.module else None
        if module:
            self.all_imports.append((module, node.lineno))
            if self.is_in_conditional(node):
                self.conditional_imports.append((module, node.lineno))
        self.generic_visit(node)

    def is_in_conditional(self, node: ast.Import) -> bool:
        # check whether the import code is in a conditional code block
        parent = getattr(node, 'parent', None)
        while parent:
            if isinstance(parent, (ast.If, ast.Try, ast.FunctionDef)):
                return True
            parent = getattr(parent, 'parent', None)
        return False


def analyze_imports(source_code: str) -> tuple:
    tree = ast.parse(source_code)

    # add parent attribute to each node
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node

    analyzer = ImportAnalyzer()
    analyzer.visit(tree)
    
    return analyzer.all_imports, analyzer.conditional_imports


def get_deps_from_pip(package_name: str, site_packages_path: str) -> dict:
    if os.path.exists(site_packages_path):
        sys.path.insert(0, site_packages_path)
    else:
        raise ValueError(f"Site-packages path not found: {site_packages_path}")    
    pkg_resources.working_set = pkg_resources.WorkingSet(sys.path)
    
    pkg2import_pkgs = {}
    for pkg in package_name:
        try:
            distribution = pkg_resources.get_distribution(pkg)
            dependencies = distribution.requires()
            pkg2import_pkgs[pkg] = [dependency.project_name for dependency in dependencies]
        except:
            pkg2import_pkgs[pkg] = []
    
    return pkg2import_pkgs


def pyfile_depends(path: str) -> List[str]:
    # get all import libraries and conditional imports
    try:
        code = open(path, 'r', errors='ignore').read()
        all_imports, conditional_imports = analyze_imports(code)
    except:
        logging.info(f"Failed to analyze imports in {path}.")
        return pyfile_depends_else(path), []
    all_imports = list(set(all_imports))
    conditional_imports = list(set(conditional_imports))
    return [imp[0] for imp in all_imports], [imp[0] for imp in conditional_imports]


class IDManager:
    @staticmethod
    def get_uuid() -> str:
        idstring = uuid4()
        return f"urn:uuid:{idstring}"

    @staticmethod
    def get_docID() -> str:
        idstring = IDManager.get_uuid()
        return idstring

    @staticmethod
    def get_pkgID(
        pkgtype: Optional[str] = None, 
        name: Optional[str] = None, 
        version: Optional[str] = None, 
        namespace: Optional[str] = None, 
        qualifiers: Optional[str] = None, 
        subpath: Optional[str] = None, 
        url: Optional[str] = None
    ) -> str:
        if pkgtype and name:
            idstring = PackageURL(
                type = pkgtype, 
                namespace = namespace, 
                name = name, 
                version = version, 
                qualifiers = qualifiers, 
                subpath = subpath
            ).to_string()
        elif url:
            temID = url2purl.get_purl(url)
            if not pkgtype:
                pkgtype = temID.type
            if not namespace:
                namespace = temID.namespace
            if not name:
                name = temID.name
            if not version:
                version = temID.version
            if not qualifiers:
                qualifiers = temID.qualifiers
            if not subpath:
                subpath = temID.subpath
            idstring = PackageURL(
                type = pkgtype, 
                namespace = namespace, 
                name = name, 
                version = version, 
                qualifiers = qualifiers, 
                subpath = subpath
            ).to_string()
        else:
            idstring = IDManager.get_uuid()
        return idstring

    @staticmethod
    def get_innerID() -> str:
        idstring = IDManager.get_uuid()
        return idstring
