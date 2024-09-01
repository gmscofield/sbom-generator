from jinja2 import Environment, FileSystemLoader, meta
import yaml
from typing import Optional
from .utils import ALGOLIST, parse_depend, component_meta_template, str2license, IDManager
from ....output import middleware


def parse_metayaml_meta(meta_path: str) -> dict:
    root, file = meta_path.rsplit('/', 1)
    env = Environment(loader=FileSystemLoader(root))
    ast = env.parse(open(meta_path, "r", errors='ignore').read())
    undeclared_set = meta.find_undeclared_variables(ast)

    undeclared_dict = {}
    for item in undeclared_set:
        undeclared_dict[item] = undeclared_exception

    template = env.get_template(file)
    rendered_yaml = template.render(undeclared_dict)
    parsed_yaml = yaml.safe_load(rendered_yaml)
    return parsed_yaml


def undeclared_exception(*args) -> str:
    return "default_undeclared_exception"


def metayaml_check(content: Optional[str]) -> Optional[str]:
    if not content or "default_undeclared_exception" in content:
        return None
    else:
        return content


def analyze_metayaml_meta(meta_path: str) -> dict:
    root_name = None
    yamlpath = (
        "/info/recipe.tar-extract/recipe/meta.yaml",
        "/info/recipe/recipe/meta.yaml",
        "/conda.recipe/meta.yaml", 
        "/ci/meta.yaml", 
        "/meta.yaml"
    )
    for path in yamlpath:
        if meta_path.endswith(path):
            res = meta_path.removesuffix(path)
            root_name = res.split("/")[-1]
            break
    
    meta = component_meta_template()
    if not root_name:
        return meta
    
    parsed_yaml = parse_metayaml_meta(meta_path)
    # package
    pkg_name = metayaml_check(parsed_yaml.get("package", {}).get("name", None))
    if not pkg_name:
        pkg_name = root_name

    pkg_version = metayaml_check(parsed_yaml.get("package", {}).get("version", None))
    pkg_checksum = []
    
    # source
    source = parsed_yaml.get("source", {})
    for algo in ALGOLIST:
        checksum = metayaml_check(source.get(algo.lower(), None))
        if not checksum:
            checksum = metayaml_check(source.get(algo, None))
        if checksum:
            pkg_checksum.append(
                middleware.Hash(
                    alg=algo,
                    value=checksum
                )
            )
    
    # about
    about = parsed_yaml.get("about", {})
    description = metayaml_check(about.get("description", None))
    if not description:
        description = metayaml_check(about.get("summary", None))
    pkg_sourceRepo = metayaml_check(about.get("dev_url", None))
    pkgID = IDManager.get_pkgID(pkgtype = "conda", name = pkg_name, version = pkg_version, url = pkg_sourceRepo)
    
    pkg_ref = []
    doc_url = metayaml_check(about.get("doc_url", None))
    if doc_url:
        pkg_ref.append(
            middleware.ExternalReference(
                url=doc_url,
                type="documentation",
            )
        )
    doc_source_url = metayaml_check(about.get("source_url", None))
    if doc_source_url:
        pkg_ref.append(
            middleware.ExternalReference(
                url=doc_source_url,
                type="website"
            )
        )
    
    # requirements
    requirements = parsed_yaml.get("requirements", {})
    builddepends = set()
    dependson = []
    for time, depends in requirements.items():
        if time == "build":
            for depend in depends:
                if metayaml_check(depend):
                    builddepends.add(parse_depend(depend))
        elif time == "run":
            for depend in depends:
                if metayaml_check(depend) and isinstance(depend, str):
                    dependson.append(parse_depend(depend))
    builddepends = list(builddepends)
    
    meta["component"] = middleware.Component(
        type="Package: LIBRARY",
        name=pkg_name,
        ID=pkgID,
        version=pkg_version,
        description=description,
        checksum=pkg_checksum,
        licenses=str2license(metayaml_check(about.get("license", None))),
        external_references=pkg_ref if pkg_ref else None,
    )
    meta["dependson"] = {"root": dependson}
    if builddepends:
        meta["relationships"]["builddepends"] = {"root": builddepends}
    meta["component"].homepage = metayaml_check(about.get("home", None))
    meta["component"].download_location = metayaml_check(source.get("url", None))
    meta["component"].source_repo = pkg_sourceRepo

    return meta


def analyze_condayml_meta(meta_path: str) -> dict:
    meta = component_meta_template()
    with open(meta_path, 'r', encoding='utf-8', errors='ignore') as f:
        result = yaml.load(f.read(), Loader=yaml.FullLoader)
    
    pkgName = result.get('name', None)
    if pkgName:
        meta["component"] = middleware.Component(type="Package: LIBRARY", name=pkgName)
    depends = result.get('dependencies', [])
    dependson = []
    for depend in depends:
        if isinstance(depend, dict):
            key, value = list(depend.items())[0]
            if key == "pip":
                for v in value:
                    if isinstance(v, str):
                        dependson.append(parse_depend(v))
        else:
            if isinstance(depend, str):
                if "python=" in depend:
                    continue
                dependson.append(parse_depend(depend))
    meta["dependson"] = {"root": dependson}
    return meta


def analyze_environmentyaml_meta(meta_path: str) -> dict:
    analyze_condayml_meta(meta_path)
