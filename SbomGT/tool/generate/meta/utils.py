import os
import ast
import pandas as pd
import re
from uuid import uuid4
from packageurl import PackageURL
from packageurl.contrib import url2purl
from typing import Optional, List
from ....output import middleware
from ....schema.cdx_model import spdx



ALGOLIST = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512", 
            "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3", "MD2", "MD4", "MD5", "MD6", "ADLER32"]

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


def pyfile_depends(filename: str) -> List[str]:
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
