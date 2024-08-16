from jinja2 import Environment, FileSystemLoader, meta
import yaml
from typing import Dict
from .utils import algoList, parse_depend, uri2name, pkg_meta_template
from ....sbomModel.universal import IDManager, Ref


def parse_metayaml_meta(meta_path):
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


def undeclared_exception(*args):
    return "default_undeclared_exception"


def metayaml_check(content):
    if not content or "default_undeclared_exception" in content:
        return None
    else:
        return content


def analyze_metayaml_meta(meta_path, level = 1):
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
    
    if not root_name:
        return None
    
    meta = pkg_meta_template(level)
    parsed_yaml = parse_metayaml_meta(meta_path)
    # package
    pkg_name = metayaml_check(parsed_yaml.get("package", {}).get("name", None))
    if not pkg_name:
        pkg_name = root_name

    pkg_version = metayaml_check(parsed_yaml.get("package", {}).get("version", None))
    pkg_checksum = []
    
    # source

    source = parsed_yaml.get("source", {})
    for algo in algoList:
        checksum = metayaml_check(source.get(algo, None))
        if checksum:
            pkg_checksum.append({"Algorithm": algo, "Checksum": checksum})
    
    # about
    about = parsed_yaml.get("about", {})
    pkg_sourceRepo = metayaml_check(about.get("dev_url", None))
    pkgID = IDManager.get_pkgID(pkgtype = "conda", name = pkg_name, version = pkg_version, url = pkg_sourceRepo)
    pkg_license = metayaml_check(about.get("license", None))
    ref1 = metayaml_check(about.get("doc_url", None))
    pkg_ref = Ref()
    if ref1:
        pkg_ref.insert(name = uri2name(ref1), docURI = ref1)

    if level == 3:
        pkg_homepage = metayaml_check(about.get("home", None))
        pkg_download = metayaml_check(source.get("url", None))
        pkg_valid = {"resourceID": pkgID, "downloadLocation": pkg_download,
                    "sourceRepo": pkg_sourceRepo, "homepage": pkg_homepage}

    # print(pkg_name, pkg_version, pkg_checksum, requirements, pkg_license, pkg_homepage, pkg_sourceRepo, pkg_ref, sep='\n')
    # requirements
    requirements = parsed_yaml.get("requirements", {})
    builddepends = set()
    dependson = []
    for time, depends in requirements.items():
        if time == "build" or time == "host":
            for depend in depends:
                if metayaml_check(depend):
                    builddepends.add(parse_depend(depend))
        elif time == "run":
            for depend in depends:
                if metayaml_check(depend) and isinstance(depend, str):
                    dependson.append(parse_depend(depend))
    builddepends = list(builddepends)
    
    meta["pkg"] = {
        "pkgName": pkg_name, 
        "pkgID": pkgID, 
        "pkgChecksum": pkg_checksum, 
        "declaredLicense": pkg_license, 
        "pkgRef": pkg_ref,
        "version": pkg_version
    }
    meta["builddepends"] = builddepends
    meta["dependson"] = dependson
    if level == 3:
        meta["pkgValid"] = pkg_valid

    return meta


def analyze_condayml_meta(meta_path, level = 1):
    meta = pkg_meta_template(level)
    with open(meta_path, 'r', encoding='utf-8', errors='ignore') as f:
        result = yaml.load(f.read(), Loader=yaml.FullLoader)
    
    meta["pkg"]["pkgName"] = result.get('name', None)
    depends = result.get('dependencies', [])
    for depend in depends:
        if isinstance(depend, Dict):
            key, value = list(depend.items())[0]
            if key == "pip":
                for v in value:
                    if isinstance(v, str):
                        meta["dependson"].append(parse_depend(v))
        else:
            if isinstance(depend, str):
                meta["dependson"].append(parse_depend(depend))
    
    return meta
    
