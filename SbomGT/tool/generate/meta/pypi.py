import toml
import json
import os
from typing import List, Dict
from scancode_toolkit.src.packagedcode.pypi_setup_py import parse_setup_py
import pip_requirements_parser
from ....output import middleware
from .utils import ALGOLIST, parse_depend, name_email_str2ind, component_meta_template, str2license, IDManager, get_imports

# relationships: testdepends, builddepends, devdepends


# setup.py
def analyze_setup_meta(path: str) -> dict:
    meta = component_meta_template()
    parse_file = parse_setup_py(path)
    homepage = parse_file.get("url", None)
    doc = parse_file.get("project_urls", {})
    exRefs = []
    for key, value in doc.items():
        if key != "Source":
            exRefs.append(
                middleware.ExternalReference(
                    url=value,
                    comment=key,
                    type="website",
                )
            )
    name = parse_file.get("name", None)
    if not name:
        name = path.split(os.sep)[-2]
    meta["component"] = middleware.Component(
        type="Package: LIBRARY",
        name=name,
        version=parse_file.get("version", None),
        description=parse_file.get("description", None),
        ID=IDManager.get_pkgID(pkgtype = "pypi", name = name, version = parse_file.get("version", None), url = homepage),
        licenses=str2license(parse_file.get("license", None)),
        external_references=exRefs if exRefs else None,
    )
    
    dependson = []
    for depend in parse_file.get("install_requires", []):
        if isinstance(depend, str):
            dependson.append(parse_depend(depend))
    
    for depend in parse_file.get("requires", []):
        if isinstance(depend, str):
            dependson.append(parse_depend(depend))
    meta["dependson"]["root"] = dependson
    
    testdepends = []
    for depend in parse_file.get("tests_require", []):
        if isinstance(depend, str):
            testdepends.append(parse_depend(depend))
    if testdepends:
        meta["relationships"]["testdepends"]["root"] = testdepends

    meta["component"].download_location = parse_file.get("download_url", None)
    meta["component"].source_repo = parse_file.get("project_urls", {}).get("Source", None)
    meta["component"].homepage = homepage
    meta["component"].originator = [name_email_str2ind(parse_file.get("author", None), parse_file.get("author_email", None))]
    meta["component"].supplier = name_email_str2ind(parse_file.get("maintainer", None), parse_file.get("maintainer_email", None))
    
    return meta


# pyproject.toml
def in2pyproject(parsed_toml: dict, result: dict, url: str = "") -> None:
    for key, value in parsed_toml.items():
        if key == "name":
            if not result["pkg"].get("pkgName", None):
                result["pkg"]["pkgName"] = value
        elif key == "version":
            if not result["pkg"].get("version", None):
                result["pkg"]["version"] = value
        elif key == "license":
            if isinstance(value, str):
                result["pkg"]["declaredLicense"] = value
            elif isinstance(value, dict):
                result["pkg"]["declaredLicense"] = value.get("text", None)
        elif key == "description":
            result["pkg"]["description"] = value
        elif key.lower() == "copyright":
            result["pkg"]["copyright"] = value
        elif key == "authors" or key == "author":
            result["pkgValid"]["originator"] = value
        elif key in ALGOLIST or key.upper() in ALGOLIST:
            result["pkg"]["pkgChecksum"].append(
                middleware.Hash(
                    alg=key,
                    value=value,
                )
            )
        elif key == "dependencies" or key == "dependency":
            if isinstance(value, Dict):
                for depend, version in value.items():
                    if isinstance(version, Dict):
                        result["dependson"].append({depend: (version.get("version", None), get_imports(depend))})
                    elif isinstance(version, str):
                        result["dependson"].append({depend: (version, get_imports(depend))})
            elif isinstance(value, List):
                for depend in value:
                    if isinstance(depend, str):
                        result["dependson"].append(parse_depend(depend))
        elif key == "dev-dependencies" or key == "dev-dependency" or key == "dev":
            if key == "dev":
                if isinstance(value, Dict):
                    builds = value.get("dependencies", {})
                else:
                    builds = value
            else:
                builds = value
            if isinstance(builds, Dict):
                for depend, version in builds.items():
                    if isinstance(version, Dict):
                        result["builddepends"].append({depend: version.get("version", None)})
                    elif isinstance(version, str):
                        result["builddepends"].append({depend: version})
            elif isinstance(builds, List):
                for depend in builds:
                    if isinstance(depend, str):
                        result["builddepends"].append(parse_depend(depend))
        elif key == "repo" or key == "repository" or key == "Repository" or \
            key == "vcs" or key == "vcs_url" or key == "vcs-url" or key == "VCS-URL":
            result["pkgValid"]["sourceRepo"] = value
            url = value
        elif key == "documentation":
            result["pkg"]["pkgRef"].append(
                middleware.ExternalReference(
                    url=value,
                    type="documentation",
                )
            )
        if key.lower() == "homepage":
            result["pkgValid"]["homepage"] = value
        elif key.lower() == "download":
            result["pkgValid"]["downloadLocation"] = value
        if isinstance(value, Dict):
            in2pyproject(value, result, url)
        elif isinstance(value, List):
            for item in value:
                if isinstance(item, Dict):
                    in2pyproject(item, result, url)


def analyze_pyproject_meta(path: str) -> dict:
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = {"pkg": {}, "dependson": [], "builddepends": [], "pkgValid": {}}
    meta["pkg"]["pkgName"] = None
    meta["pkg"]["version"] = None
    meta["pkg"]["declaredLicense"] = None
    meta["pkg"]["pkgChecksum"] = []
    meta["pkg"]["pkgID"] = None
    meta["pkg"]["pkgRef"] = []
    url = ""
    in2pyproject(parsed_toml, meta, url)
    if not meta["pkg"]["pkgName"]:
        meta["pkg"]["pkgName"] = path.split(os.sep)[-2]
    pkgID = IDManager.get_pkgID(pkgtype = "pypi", name = meta["pkg"]["pkgName"], version = meta["pkg"].get("version", None), url = url)
    
    originator = []
    if meta["pkgValid"].get("originator", None):
        if isinstance(meta["pkgValid"]["originator"], str):
            originator = [name_email_str2ind(meta["pkgValid"]["originator"], None)]
        elif isinstance(meta["pkgValid"]["originator"], List):
            for info in meta["pkgValid"]["originator"]:
                if isinstance(info, str):
                    originator.append(name_email_str2ind(info, None))
    
    pkg_meta = component_meta_template()
    pkg_meta["component"] = middleware.Component(
        type="Package: LIBRARY",
        name=meta["pkg"]["pkgName"],
        version=meta["pkg"]["version"],
        ID=pkgID,
        licenses=str2license(meta["pkg"]["declaredLicense"]),
        description=meta["pkg"].get("description", None),
        checksum=meta["pkg"]["pkgChecksum"] if meta["pkg"]["pkgChecksum"] else None,
        external_references=meta["pkg"]["pkgRef"] if meta["pkg"]["pkgRef"] else None,
        homepage=meta["pkgValid"].get("homepage", None),
        download_location=meta["pkgValid"].get("downloadLocation", None),
        source_repo=meta["pkgValid"].get("sourceRepo", None),
        originator=originator if originator else None,
    )
    pkg_meta["dependson"]["root"] = meta["dependson"]
    pkg_meta["relationships"]["devdepends"] = {}
    pkg_meta["relationships"]["devdepends"]["root"] = meta["builddepends"]
    
    return pkg_meta


# requirements.txt
def analyze_requirements_meta(path: str) -> dict:
    req_file = pip_requirements_parser.RequirementsFile.from_file(
        filename = path,
        include_nested = False,
    )
    if not req_file or not req_file.requirements:
        return []

    dependson = []
    meta = component_meta_template()
    meta["relationships"] = {
        "testdepends": {},
        "devdepends": {},
        "builddepends": {},
    }
    for req in req_file.requirements:
        requirement = req.dumps()
        if path.endswith('dev.txt'):
            build_dep = meta["relationships"].get("devdepends", [])
            build_dep.append(parse_depend(requirement))
            meta["relationships"]["devdepends"]["root"] = build_dep
        elif path.endswith(('test.txt', 'tests.txt')):
            test_dep = meta["relationships"].get("testdepends", [])
            test_dep.append(parse_depend(requirement))
            meta["relationships"]["testdepends"]["root"] = test_dep
        else:
            dependson.append(parse_depend(requirement))
    meta["dependson"]["root"] = dependson

    return meta


# Pipfile
def analyze_pipfile_meta(path: str) -> dict:
    # toml file
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = component_meta_template()

    dependson = []
    for name, version in parsed_toml.get("packages", {}).items():
        if not version or isinstance(version, str):
            if version == "*":
                version = None
            dependson.append({name: (version, get_imports(name))})
    meta["dependson"]["root"] = dependson
    
    build_dep = []
    for name, version in parsed_toml.get("dev-packages", {}).items():
        if not version or isinstance(version, str):
            if version == "*":
                version = None
            build_dep.append({name: (version, get_imports(name))})
    if build_dep:
        meta["relationships"]["devdepends"] = {}
        meta["relationships"]["devdepends"]["root"] = build_dep
    return meta


# tree
# Pipfile.lock
def analyze_pipfileLock_meta(path: str) -> dict:
    with open(path) as f:
        content = f.read()

    data = json.loads(content)
    meta = component_meta_template()
    meta["component"] = []
    depends = data.get("default", {})
    dependson = []
    for name, info in depends.items():
        version = info.get("version", None)
        if version == "*":
            version = None
        if version:
            version = version.strip("").strip("==")
        checksums = []
        if info.get("hashes", None):
            for comp_hash in info["hashes"]:
                if ":" in comp_hash:
                    alg, value = comp_hash.split(":")
                    checksums.append(
                        middleware.Hash(
                            alg=alg,
                            value=value
                        )
                    )
        meta["component"].append(
            middleware.Component(
                type="Package: LIBRARY",
                name=name,
                version=version,
                ID=IDManager.get_pkgID(pkgtype="pypi", name=name, version=version),
                checksum=checksums if checksums else None,
            )
        )
        dependson.append({name: (version, get_imports(name))})
    meta["dependson"]["root"] = dependson
    
    dev_dep = []
    devdepends = data.get("develop", {})
    for name, info in devdepends.items():
        version = info.get("version", None)
        if version == "*":
            version = None
        if version:
            version = version.strip("").strip("==")
        checksums = []
        if info.get("hashes", None):
            for comp_hash in info["hashes"]:
                if ":" in comp_hash:
                    alg, value = comp_hash.split(":")
                    checksums.append(
                        middleware.Hash(
                            alg=alg,
                            value=value
                        )
                    )
        meta["component"].append(
            middleware.Component(
                type="Package: LIBRARY",
                name=name,
                version=version,
                ID=IDManager.get_pkgID(pkgtype="pypi", name=name, version=version),
                checksum=checksums if checksums else None,
            )
        )
        dev_dep.append({name: (version, get_imports(name))})
    
    meta["relationships"]["devdepends"] = {}
    meta["relationships"]["devdepends"]["root"] = dev_dep
    
    return meta


# tree
# poetry.lock
def analyze_poetry_meta(path: str) -> dict:
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = component_meta_template()
    meta["component"] = []
    meta["dependson"] = {}
    comp_dic = {}
    pkg = parsed_toml.get("package", [])
    hashes = parsed_toml.get("metadata", {}).get("files", {})
    for info in pkg:
        if info.get("name", None):
            version = info.get("version", None)
            if version == "*":
                version = None
            checksum = []
            if hashes.get(info["name"], None):
                for comp_hash in hashes[info["name"]]:
                    if ":" in comp_hash["hash"]:
                        alg, value = comp_hash["hash"].split(":")
                        checksum.append(
                            middleware.Hash(
                                alg=alg,
                                value=value,
                            )
                        )
                
            comp = middleware.Component(
                type="Package: LIBRARY",
                name=info["name"],
                version=version,
                description=info.get("description", None),
                ID=IDManager.get_pkgID(pkgtype="pypi", name=info.get("name", None), version=info.get("version", None)),
                checksum=checksum if checksum else None,
            )
            meta["component"].append(comp)
            comp_dic[info["name"]] = comp
    
    test_depends = {}
    dev_depends = {}
    build_depends = {}
    for info in pkg:
        info_dep = info.get("dependencies", {})
        root_comp = comp_dic.get(info.get("name", None), None)
        if not root_comp:
            continue
        for dep, version in info_dep.items():
            comp = comp_dic.get(dep, None)
            if comp:
                if not comp.version:
                    if isinstance(version, str) and version != "*":
                        comp.version = version
                    elif isinstance(version, dict):
                        version = version.get("version", None)
                        if version == "*":
                            version = None
                        comp.version = version
                comp_dep = meta["dependson"].get(root_comp.name, [])
                comp_dep.append({comp.name: (comp.version, get_imports(comp.name))})
                meta["dependson"][root_comp.name] = comp_dep
        extras = info.get("extras", {})
        for key, value in extras.items():
            if "test" in key:
                if isinstance(value, List):
                    deps = []
                    for v in value:
                        comp = comp_dic.get(v, None)
                        if comp:
                            deps.append({comp.name: (comp.version, get_imports(comp.name))})
                    test_depends[root_comp.name] = deps
            elif "dev" in key:
                if isinstance(value, List):
                    deps = []
                    for v in value:
                        comp = comp_dic.get(v, None)
                        if comp:
                            deps.append({comp.name: (comp.version, get_imports(comp.name))})
                    dev_depends[root_comp.name] = deps
            elif "build" in key:
                if isinstance(value, List):
                    deps = []
                    for v in value:
                        comp = comp_dic.get(v, None)
                        if comp:
                            deps.append({comp.name: (comp.version, get_imports(comp.name))})
                    build_depends[root_comp.name] = deps
    
    meta["relationships"]["testdepends"] = test_depends
    meta["relationships"]["devdepends"] = dev_depends
    meta["relationships"]["builddepends"] = build_depends
    return meta


# tree
# pdm.lock
def analyze_pdm_meta(path: str) -> dict:
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = component_meta_template()
    meta["component"] = []
    meta["dependson"] = {}
    comp_dic = {}
    pkg = parsed_toml.get("package", [])
    hashes = parsed_toml.get("metadata", {}).get("files", {})
    for info in pkg:
        if info.get("name", None):
            version = info.get("version", None)
            if version == "*":
                version = None
            checksum = []
            if hashes.get(" ".join([info["name"], version]), None):
                for comp_hash in hashes[info["name"]]:
                    if ":" in comp_hash["hash"]:
                        alg, value = comp_hash["hash"].split(":")
                        checksum.append(
                            middleware.Hash(
                                alg=alg,
                                value=value,
                            )
                        )
            if info.get("files", None):
                for comp_hash in info["files"]:
                    if ":" in comp_hash["hash"]:
                        alg, value = comp_hash["hash"].split(":")
                        checksum.append(
                            middleware.Hash(
                                alg=alg,
                                value=value,
                            )
                        )
            
            comp = middleware.Component(
                type="Package: LIBRARY",
                name=info["name"],
                version=version,
                description=info.get("summary", None),
                ID=IDManager.get_pkgID(pkgtype="pypi", name=info.get("name", None), version=info.get("version", None)),
                checksum=checksum if checksum else None,
            )
            meta["component"].append(comp)
            comp_dic[info["name"]] = comp
    
    test_depends = {}
    dev_depends = {}
    build_depends = {}
    for info in pkg:
        info_dep = info.get("dependencies", [])
        root_comp = comp_dic.get(info.get("name", None), None)
        if not root_comp:
            continue
        defalt = False
        test = False
        dev = False
        build = False
        if info.get("groups", None):
            for grp in info["groups"]:
                if "default" in grp:
                    defalt = True
                if "test" in grp:
                    test = True
                if "dev" in grp:
                    dev = True
                if "build" in grp:
                    build = True
        
        for dep_info in info_dep:
            dep_info = parse_depend(dep_info.split(";")[0])
            dep = list(dep_info.keys())[0]
            version = list(dep_info.values())[0][0]
            comp = comp_dic.get(dep, None)
            if comp:
                if not comp.version:
                    if isinstance(version, str) and version != "*":
                        comp.version = version
                    elif isinstance(version, dict):
                        version = version.get("version", None)
                        if version == "*":
                            version = None
                        comp.version = version
                if defalt:
                    comp_dep = meta["dependson"].get(root_comp.name, [])
                    comp_dep.append({comp.name: (comp.version, get_imports(comp.name))})
                    meta["dependson"][root_comp.name] = comp_dep
                if test:
                    deps = test_depends.get(root_comp.name, [])
                    deps.append({comp.name: (comp.version, get_imports(comp.name))})
                    test_depends[root_comp.name] = deps
                if dev:
                    deps = dev_depends.get(root_comp.name, [])
                    deps.append({comp.name: (comp.version, get_imports(comp.name))})
                    dev_depends[root_comp.name] = deps
                if build:
                    deps = build_depends.get(root_comp.name, [])
                    deps.append({comp.name: (comp.version, get_imports(comp.name))})
                    build_depends[root_comp.name] = deps
    
    meta["relationships"]["testdepends"] = test_depends
    meta["relationships"]["devdepends"] = dev_depends
    meta["relationships"]["builddepends"] = build_depends
    return meta
