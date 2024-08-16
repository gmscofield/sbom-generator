import toml
import json
from typing import List, Dict
from scancode_toolkit.src.packagedcode.pypi_setup_py import parse_setup_py
import pip_requirements_parser

from ....sbomModel.universal import IDManager, Ref
from .utils import algoList, parse_depend, uri2name, name_email_string, pkg_meta_template
from .val_depend import get_imports


# FIELDS = {
#     # 'author_email',
#     # 'author',
#     # 'download_url',
#     # 'install_requires',
#     # 'license',
#     # 'maintainer_email',
#     # 'maintainer',
#     # 'name',
#     # 'package_dir',       # source code direction
#     # 'project_urls',
#     # 'requires', # with install_requires
#     # 'setup_requires',
#     # 'tests_require',
#     # 'url',
#     # 'version',
# }


# setup.py
def analyze_setup_meta(path, level = 1):
    meta = pkg_meta_template(level)
    parse_file = parse_setup_py(path)
    meta["pkg"]["pkgName"] = parse_file.get("name", None)
    meta["pkg"]["version"] = parse_file.get("version", None)
    meta["pkg"]["declaredLicense"] = parse_file.get("license", None)
    url = parse_file.get("url", None)
    meta["pkg"]["pkgID"] = IDManager.get_pkgID(pkgtype = "pypi", name = meta["pkg"]["pkgName"], version = meta["pkg"]["version"], url = url)
    meta["pkg"]["pkgRef"] = Ref()
    doc = parse_file.get("project_urls", {})

    for key, value in doc.items():
        if key != "Source":
            meta["pkg"]["pkgRef"].insert(name = key, docURI = value)
    
    for depend in parse_file.get("install_requires", []):
        if isinstance(depend, str):
            meta["dependson"].append(parse_depend(depend))
    
    for depend in parse_file.get("requires", []):
        if isinstance(depend, str):
            meta["dependson"].append(parse_depend(depend))

    for depend in parse_file.get("setup_requires", []):
        if isinstance(depend, str):
            meta["builddepends"].append(parse_depend(depend))
    
    for depend in parse_file.get("tests_require", []):
        if isinstance(depend, str):
            meta["builddepends"].append(parse_depend(depend))

    if level == 3:
        meta["pkgValid"]["downloadLocation"] = parse_file.get("download_url", None)
        meta["pkgValid"]["sourceRepo"] = parse_file.get("project_urls", {}).get("Source", None)
        meta["pkgValid"]["homepage"] = url
        meta["pkgValid"]["originator"] = name_email_string(parse_file.get("author", None), parse_file.get("author_email", None))
        meta["pkgValid"]["supplier"] = name_email_string(parse_file.get("maintainer", None), parse_file.get("maintainer_email", None))
        meta["pkgValid"]["resourceID"] = meta["pkg"]["pkgID"]

    return meta


# pyproject.toml
def in2pyproject(parsed_toml, result, level = 1, url = ""):
    for key, value in parsed_toml.items():
        if key == "name":
            if not result["pkg"].get("pkgName", None):
                result["pkg"]["pkgName"] = value
        elif key == "version":
            if not result["pkg"].get("version", None):
                result["pkg"]["version"] = value
        elif key == "license":
            result["pkg"]["declaredLicense"] = value
        elif key in algoList:
            result["pkg"]["pkgChecksum"].append({"Algorithm": key, "Checksum": value})
        elif key == "dependencies" or key == "dependency":
            if isinstance(value, Dict):
                for depend, version in value.items():
                    if isinstance(version, Dict):
                        result["dependson"].append({depend: (version.get("version", None), get_imports(depend))})
                    elif isinstance(version, str):
                        result["dependson"].append({depend: (version, get_imports(depend))})
                    else:
                        raise Exception("Invalid dependson version", depend, version)
            elif isinstance(value, List):
                for depend in value:
                    if isinstance(depend, str):
                        result["dependson"].append(parse_depend(depend))
            else:
                raise Exception("Invalid dependson value", value)
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
                    else:
                        raise Exception("Invalid builddepends version", depend, version)
            elif isinstance(builds, List):
                for depend in builds:
                    if isinstance(depend, str):
                        result["builddepends"].append(parse_depend(depend))
            else:
                raise Exception("Invalid builddepends value", builds)
        elif key == "repo" or key == "repository" or key == "Repository" or \
            key == "vcs" or key == "vcs_url" or key == "vcs-url" or key == "VCS-URL":
            if level == 3:
                result["pkgValid"]["sourceRepo"] = value
            url = value
        elif key == "documentation":
            result["pkg"]["pkgRef"].insert(name = uri2name(value), docURI = value)
        if level == 3:
            if key == "homepage" or key == "Homepage":
                result["pkgValid"]["homepage"] = value
            elif key == "download" or key == "Download":
                result["pkgValid"]["downloadLocation"] = value
        if isinstance(value, Dict):
            in2pyproject(value, result, level, url)
        elif isinstance(value, List):
            for item in value:
                if isinstance(item, Dict):
                    in2pyproject(item, result, level, url)


def analyze_pyproject_meta(path, level = 1):
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = pkg_meta_template(level)
    meta["pkg"]["pkgName"] = None
    meta["pkg"]["version"] = None
    meta["pkg"]["declaredLicense"] = None
    meta["pkg"]["pkgChecksum"] = []
    meta["pkg"]["pkgID"] = None
    meta["pkg"]["pkgRef"] = Ref()
    url = ""
    in2pyproject(parsed_toml, meta, level, url)
    if not meta["pkg"]["pkgName"]:
        meta["pkg"]["pkgName"] = path.split("/")[-2] if len(path.split("/")) > 1 else path.split("/")[-1]
    pkgID = IDManager.get_pkgID(pkgtype = "pypi", name = meta["pkg"]["pkgName"], version = meta["pkg"].get("version", None), url = url)
    meta["pkg"]["pkgID"] = pkgID
    if level == 3:
        meta["pkgValid"]["resourceID"] = pkgID
    return meta


# requirements.txt
def analyze_requirements_meta(path, level = 1):
    req_file = pip_requirements_parser.RequirementsFile.from_file(
        filename = path,
        include_nested = False,
    )
    if not req_file or not req_file.requirements:
        return []

    meta = pkg_meta_template(level)
    for req in req_file.requirements:
        requirement = req.dumps()
        if path.endswith(
            (
                'dev.txt',
                'test.txt',
                'tests.txt',
            )
        ):
            meta["builddepends"].append(parse_depend(requirement))
        else:
            meta["dependson"].append(parse_depend(requirement))

    return meta


# Pipfile
def analyze_pipfile_meta(path, level = 1):
    # toml file
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = pkg_meta_template(level)
    if level == 3:
        source = parsed_toml.get("source", [])
        for info in source:
            key, value = list(info.items())[0]
            if key == "url":
                meta["pkgValid"]["downLoadLocation"] = value

    for name, version in parsed_toml.get("packages", {}).items():
        if not version or isinstance(version, str):
            if version == "*":
                version = None
            meta["dependson"].append({name: (version, get_imports(name))})
    
    for name, version in parsed_toml.get("dev-packages", {}).items():
        if not version or isinstance(version, str):
            if version == "*":
                version = None
            meta["builddepends"].append({name: version})
    return meta


# Pipfile.lock
def analyze_pipfileLock_meta(path, level = 1):
    with open(path) as f:
        content = f.read()

    data = json.loads(content)
    meta = pkg_meta_template(level)
    sources = meta.get("_meta", {}).get("sources", [])
    if sources:
        meta["pkg"]["pkgRef"] = Ref()
        for source in sources:
            name = source.get("name", None)
            url = source.get("url", None)
            if name and url:
                meta["pkg"]["pkgRef"].insert(name = source.get("name", None), docURI = source.get("url", None))

    depends = data.get("default", {})
    for name, info in depends.items():
        version = info.get("version", None)
        if version == "*":
            version = None
        meta["dependson"].append({name: (version, get_imports(name))})
    
    builddepends = data.get("develop", {})
    for name, info in depends.items():
        version = info.get("version", None)
        if version == "*":
            version = None
        meta["builddepends"].append({name: version})
    
    return meta

# poetry.lock
def analyze_poetry_meta(path, level = 1):
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = pkg_meta_template(level)
    pkg = parsed_toml.get("package", [])
    for info in pkg:
        meta["pkg"]["pkgName"] = info.get("name", None)
        meta["pkg"]["version"] = info.get("version", None)
        dependson = info.get("dependencies", {})
        extras = info.get("extras", {})
        for key, value in extras.items():
            for v in value:
                meta["builddepends"].append(parse_depend(v))
    return meta


# pdm.lock
def analyze_pdm_meta(path, level = 1):
    f = open(path, "r", errors='ignore')
    parsed_toml = toml.loads(f.read())
    meta = pkg_meta_template(level)
    return meta