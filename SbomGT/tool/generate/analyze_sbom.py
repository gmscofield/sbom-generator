import os
import requests
import sys
import json
from packageurl import PackageURL
import pandas as pd
from typing import Optional, List, Tuple
from datetime import datetime
import logging
from scancode_toolkit.src.scancode.api import get_licenses

from .meta.pypi import analyze_pyproject_meta, analyze_requirements_meta, analyze_setup_meta, \
    analyze_pipfile_meta, analyze_pipfileLock_meta, analyze_pdm_meta, analyze_poetry_meta
from .meta.conda import analyze_metayaml_meta, analyze_condayml_meta, analyze_environmentyaml_meta
from .meta.utils import component_meta_template, name_email_str2ind, IDManager, \
    is_py_file, pyfile_depends, is_valid_purl, get_imports, str2license
from .meta.parse_pyfile import analyze_pyfile_meta, copyright_from_pkgfile
from ...output import middleware, cdx_conversion, spdx_conversion, ossbom_conversion


METAFILE2FUNC = {
    "conda.yml": analyze_condayml_meta,
    "meta.yaml": analyze_metayaml_meta,
    "environment.yaml": analyze_environmentyaml_meta,
    "Pipfile": analyze_pipfile_meta,
    "Pipfile.lock": analyze_pipfileLock_meta,
    "pyproject.toml": analyze_pyproject_meta,
    "setup.py": analyze_setup_meta,
    "poetry.lock": analyze_poetry_meta,
    "pdm.lock": analyze_pdm_meta,
    "requirements.txt": analyze_requirements_meta,
    'dev.txt': analyze_requirements_meta,
    'test.txt': analyze_requirements_meta,
    'tests.txt': analyze_requirements_meta,
}

LICENSE_LIST_VERSION = "3.23"


def merge_component(component1: Optional[middleware.Component], component2: Optional[middleware.Component]) -> Optional[middleware.Component]:
    if not component1:
        return component2
    if not component2:
        return component1
    
    name = component1.name if component1.name else component2.name
    version = component1.version
    if not version or (">" in version or "<" in version):
        if component2.version:
            version = component2.version
    id = IDManager.get_pkgID(pkgtype = "pypi", name = name, version = version)
    
    originator = None
    if component1.originator and component2.originator:
        originator = component1.originator + component2.originator
    elif component2.originator:
        originator = component1.originator
    elif component1.originator:
        originator = component2.originator
    
    supplier = component1.supplier
    if not supplier:
        if component2.supplier:
            supplier = component2.supplier
    
    publisher = component1.publisher
    if not publisher:
        if component2.publisher:
            publisher = component2.publisher
    
    licenses = component1.licenses
    if not licenses:
        if component2.licenses:
            if not licenses:
                licenses = component2.licenses
            else:
                licenses.extend(component2.licenses)
    
    copyright = component1.copyright
    if not copyright:
        if component2.copyright:
            copyright = component2.copyright
    
    checksums = component1.checksum
    if not checksums:
        if component2.checksum:
            if not checksums:
                checksums = component2.checksum
            else:
                checksums.extend(component2.checksum)
    
    exrefs = component1.external_references
    if not exrefs:
        if component2.external_references:
            if not exrefs:
                exrefs = component2.external_references
            else:
                exrefs.extend(component2.external_references)
    
    source_info = ""
    if component1.source_info:
        source_info += component1.source_info
    if component2.source_info:
        source_info += component2.source_info
    
    description = ""
    if component1.description:
        description += component1.description
    if component2.description:
        description += component2.description
    
    properties = component1.properties
    if not properties:
        if component2.properties:
            if not properties:
                properties = component2.properties
            else:
                properties.extend(component2.properties)
    
    merged_comp = middleware.Component(
        type=component1.type if component1.type else component2.type,
        name=component1.name if component1.name else component2.name,
        version=component1.version if component1.version else component2.version,
        ID=id,
        scope=component1.scope if component1.scope else component2.scope,
        originator=originator,
        supplier=supplier,
        publisher=publisher,
        group=component1.group if component1.group else component2.group,
        licenses=licenses,
        copyright=copyright,
        checksum=checksums,
        external_references=exrefs,
        verificationCodeExcludedFiles=component1.verificationCodeExcludedFiles if component1.verificationCodeExcludedFiles else component2.verificationCodeExcludedFiles,
        verificationCodeValue=component1.verificationCodeValue if component1.verificationCodeValue else component2.verificationCodeValue,
        download_location=component1.download_location if component1.download_location else component2.download_location,
        source_repo=component1.source_repo if component1.source_repo else component2.source_repo,
        homepage=component1.homepage if component1.homepage else component2.homepage,
        source_info=source_info if source_info else None,
        description=description if description else None,
        built_date=component1.built_date if component1.built_date else component2.built_date,
        valid_until_date=component1.valid_until_date if component1.valid_until_date else component2.valid_until_date,
        release_date=component1.release_date if component1.release_date else component2.release_date,
        releaseNotes=component1.releaseNotes if component1.releaseNotes else component2.releaseNotes,
        tags=component1.tags if component1.tags else component2.tags,
        signature=component1.signature if component1.signature else component2.signature,
        properties=properties,
    )
    return merged_comp


def req_pypi(pkg_name: Optional[str]) -> Optional[dict]:
    if not pkg_name:
        return None
    url = f"https://pypi.org/pypi/{pkg_name}/json"
    proxies = {
        "http_proxy": "socks5://127.0.0.1:7890", 
        "https_proxy": "socks5://127.0.0.1:7890"
    }
    try:
        response = requests.get(url, proxies = proxies)
    except:
        response = requests.get(url)
    meta = {}
    try:
        data = response.json()
        res = data.get("info", None)
    except:
        return meta
    
    if res:
        meta["declaredLicense"] = res.get("license", None)
        meta["pkgChecksum"] = res.get("checksum", None)
        meta["pkgRef"] = []
        doc = res.get("docs_url", None)
        if doc:
            meta["pkgRef"].append(
                middleware.ExternalReference(
                    url=doc,
                    type="documentation"
                )
            )
        sourceRepo = ""
        pjurls = res.get("project_urls", {})
        if pjurls:
            for key, value in pjurls.items():
                if "source" in key or "Source" in key or "repo" in key or "Repo" in key or "vcs" in key or "VCS" in key:
                    sourceRepo = value
                    break
        meta["downloadLocation"] = res.get("download_url", None)
        meta["sourceRepo"] = sourceRepo
        meta["homepage"] = res.get("home_page", None)
        author = res.get("author", None)
        author_mail = res.get("author_email", None)
        originator = [name_email_str2ind(author, author_mail)]
        meta["originator"] = originator
        
    return meta


def analyze_env(path: str) -> Optional[List[dict]]:
    logging.info("Analyze Environment...")
    dirs = os.listdir(path)
    if "lib" in dirs:
        env_flag = False
        for d in os.listdir(os.path.join(path, "lib")):
            env_path = os.path.join(path, "lib", d, "site-packages")
            if os.path.exists(env_path):
                env_flag = True
                env_pkg = env_path
                break
        if not env_flag:
            return None, None
        
        pkg_metas = []
        env_list = os.listdir(env_pkg)
        pkg2import = {}
        all_depends = {}
        tem_relations = []
        for p in env_list:
            cur_path = os.path.join(env_pkg, p)
            if "dist-info" in p:
                metadata_path = os.path.join(cur_path, "METADATA")
                info = {}
                with open(metadata_path, "r", errors="ignore") as f:
                    rows = f.readlines()
                    for row in rows:
                        i = row.find(":")
                        if i > 0:
                            info[row[:i].strip()] = row[i+1:].strip()
                
                name = info.get("Name", None)
                if not name:
                    name = p.split("-")[0]
                version = info.get("Version", None)
                if not version:
                    version = p.strip(".dist-info").split("-")[-1]
                logging.info(f"Analyzing Package {name}-{version}")
                
                description = info.get("Description", None)
                if not description:
                    description = info.get("Summary", None)
                meta = component_meta_template()
                meta["component"] = middleware.Component(
                    type="Package: LIBRARY",
                    name=name,
                    version=version,
                    ID=IDManager.get_pkgID(pkgtype = "pypi", name = name, version = version),
                    originator=[middleware.Individual(type="person", name=info.get("Author", None), email=info.get("Author-email", None))],
                    supplier=middleware.Individual(type="organization", name=info.get("Maintainer", None), email=info.get("Maintainer-email", None)),
                    licenses=[middleware.License(type="concluded", spdxID=info.get("License", None))],
                    description=description,
                    download_location=info.get("Download-url", None),
                    homepage=info.get("Home-page", None),
                    source_repo=info.get("Project-url", None),
                )
                pkg_metas.append(meta)
                
                record_path = os.path.join(env_pkg, p, "RECORD")
                df = pd.read_csv(record_path, header=None)
                import_name = set()
                for pre in list(df[0]):
                    prefix = pre.split("/")[0]
                    if not "dist-info" in prefix and not "__" in prefix and not ".." in prefix:
                        suffix = prefix.split(".")[-1]
                        if suffix == "py" or suffix == prefix:
                            import_name.add(prefix)
                pkg2import[name] = import_name
                
            elif os.path.isdir(cur_path):
                depends = []
                paths = os.walk(cur_path)
                for root, dirs, files in paths:
                    for file in files:
                        if is_py_file(file):
                            dependency = pyfile_depends(os.path.join(root, file))
                            remove_lst = []
                            for dep in dependency:
                                if (dep + ".py") in files or dep in dirs:
                                    remove_lst.append(dep)
                            for dep in remove_lst:
                                dependency.remove(dep)
                            depends.extend(dependency)
                            
                            comp_files = analyze_pyfile_meta(os.path.join(root, file))
                            if comp_files:
                                file_meta = component_meta_template()
                                for i, one_comp in enumerate(comp_files):
                                    if i == 0:
                                        file_meta["component"] = one_comp
                                        file_meta["relationships"]["contains"] = []
                                    else:
                                        file_meta["relationships"]["contains"].append(
                                            middleware.Relationship(
                                                type="CONTAINS",
                                                sourceID=file_meta["component"].ID,
                                                targetID=one_comp.ID
                                            )
                                        )
                                        one_comp_meta = component_meta_template()
                                        one_comp_meta["component"] = one_comp
                                        pkg_metas.append(one_comp_meta)
                                pkg_metas.append(file_meta)
                                tem_relations.append(
                                    middleware.Relationship(
                                        type="CONTAINS",
                                        sourceID=p,
                                        targetID=file_meta["component"].ID
                                    )
                                )
                all_depends[p] = list(set(depends))
            elif is_py_file(cur_path):
                dependency = pyfile_depends(os.path.join(root, file))
                all_depends[p.strip(".py")] = dependency
        
        for pkg in pkg_metas:
            name = pkg["component"].name
            import_name = pkg2import.get(name, [])
            depends = []
            for imp in import_name:
                if imp in all_depends:
                    depends += all_depends[imp]
                remove_rels = []
                for tem_rel in tem_relations:
                    if tem_rel.sourceID == imp:
                        remove_rels.append(tem_rel)
                        rel = tem_rel.copy()
                        rel.sourceID = pkg["component"].ID
                        pkg_contain = pkg["relationships"].get("contains", [])
                        pkg_contain.append(rel)
                        pkg["relationships"]["contains"] = pkg_contain
                for rel in remove_rels:
                    tem_relations.remove(rel)
            pkg["dependson"] = list(set(depends))
        
        return pkg_metas, pkg2import
    else:
        return None, None


def merge_depends_withenv(
    depends: dict, 
    rel_type: str, 
    relations: List[middleware.Relationship], 
    comp_dic: dict, 
    pkg2import: dict
) -> List[middleware.Relationship]:
    for comp_name, comp_deps in depends.items():
        if comp_deps:
            test_comp = comp_dic.get(comp_name, None)
            if not test_comp:
                continue
            for dep in comp_deps:
                if isinstance(dep, dict):
                    d = list(dep.keys())[0]
                    if d in comp_dic:
                        rel = middleware.Relationship(
                            type=rel_type,
                            sourceID=comp_dic[d].ID,
                            targetID=test_comp.ID
                        )
                        if not (rel in relations):
                            relations.append(rel)
                else:
                    for pkg_name, deps in pkg2import.items():
                        if dep in deps:
                            comp = comp_dic.get(pkg_name, None)
                            if comp:
                                rel = middleware.Relationship(
                                    type=rel_type,
                                    sourceID=comp.ID,
                                    targetID=test_comp.ID
                                )
                                if not (rel in relations):
                                    relations.append(rel)
    return relations


def merge_depends_withoutenv(
    depends: dict, 
    rel_type: str, 
    comp_dic: dict, 
    component_list: List, 
    relations: List
) -> Tuple:
    from_file_depends = []
    from_meta_depends = []
    for comp_name, deps in depends.items():
        if deps:
            if comp_name == "root":
                depversions = {}
                for dep in deps:
                    if isinstance(dep, str):
                        from_file_depends.append(dep)
                    else:
                        from_meta_depends.append(list(dep.keys())[0])
                        depversions.update(dep)
                
                for dep in from_file_depends:
                    possible_pkg_name = get_imports(dep)
                    mutual_names = list(possible_pkg_name.intersection(set(from_meta_depends)))
                    if mutual_names:
                        correspond_pkg = mutual_names[0]
                    else:
                        correspond_pkg = possible_pkg_name.pop()
                    if not correspond_pkg in comp_dic:
                        version = None
                        if depversions.get(correspond_pkg, None):
                            version = depversions[correspond_pkg][0]
                        comp = middleware.Component(
                            type="Package: LIBRARY",
                            name=correspond_pkg,
                            version=version,
                            ID=IDManager.get_pkgID(pkgtype = "pypi", name = correspond_pkg, version = version),
                        )
                        component_list.append(comp)
                        comp_dic[correspond_pkg] = comp
                    
                    rel = middleware.Relationship(
                        type=rel_type,
                        sourceID=comp_dic["root"].ID,
                        targetID=comp_dic[correspond_pkg].ID
                    )
                    if not rel in relations:
                        relations.append(rel)
                
                for dep in from_meta_depends:
                    if not dep in comp_dic:
                        new_comp = middleware.Component(
                            type="Package: LIBRARY",
                            name=dep,
                            version=depversions[dep][0],
                            ID=IDManager.get_pkgID(pkgtype = "pypi", name = dep, version = depversions[dep][0]),
                        )
                        component_list.append(new_comp)
                        comp_dic[dep] = new_comp
                    if rel_type != "DEPENDS_ON" and not from_file_depends:
                        rel = middleware.Relationship(
                            type=rel_type,
                            sourceID=comp_dic["root"].ID,
                            targetID=comp_dic[dep].ID
                        )
                        if not rel in relations:
                            relations.append(rel)
            else:
                if not comp_dic.get(comp_name, None):
                    comp = middleware.Component(
                        type="Package: LIBRARY",
                        name=comp_name,
                        ID=IDManager.get_pkgID(pkgtype = "pypi", name = comp_name),
                    )
                    component_list.append(comp)
                    comp_dic[comp.name] = comp
                for dep in deps:
                    pkg_name = list(dep.keys())[0]
                    if not pkg_name in comp_dic:
                        version = dep[pkg_name][0]
                        comp = middleware.Component(
                            type="Package: LIBRARY",
                            name=pkg_name,
                            version=version,
                            ID=IDManager.get_pkgID(pkgtype = "pypi", name = pkg_name, version = version),
                        )
                        component_list.append(comp)
                        comp_dic[pkg_name] = comp
                    rel = middleware.Relationship(
                        type=rel_type,
                        sourceID=comp_dic[comp_name].ID,
                        targetID=comp_dic[pkg_name].ID
                    )
                    if not rel in relations:
                        relations.append(rel)
    return comp_dic, component_list, relations


def build_bom(
    path: str, 
    model: Optional[str] = "middleware", 
    env: Optional[str] = None
) -> dict:
    comp_dic = {}
    component_list = []
    common_comp_list = []
    relations = []
    
    paths = os.walk(path)
    key_words = ["alias", "Alias", "sample", "Sample", "ci", ".git"]
    
    pkg_metas = None
    if env:
        pkg_metas, pkg2import = analyze_env(env)
    
    comp_license = None
    comp_copyright = None
    dependson = {}
    testdepends = {}
    builddepends = {}
    devdepends = {}
    for root, dirs, files in paths:
        if env and root.startswith(env):
            continue
        flag = False
        for word in key_words:
            if word in root:
                flag = True
                break
        if flag:
            continue
        if not env:
            if "lib" in dirs:
                env_flag = False
                for d in os.listdir(os.path.join(root, "lib")):
                    env_path = os.path.join(root, "lib", d, "site-packages")
                    if os.path.exists(env_path):
                        env_flag = True
                        break
                if env_flag:
                    env = root
                    pkg_metas, pkg2import = analyze_env(env)
        
        logging.info(f"Dig into {root}...")
        for file in files:
            if file in METAFILE2FUNC:
                meta_data = METAFILE2FUNC[file](os.path.join(root, file))
                if meta_data["component"]:
                    if file in ["Pipfile.lock", "poetry.lock", "pdm.lock"]:
                        for comp in meta_data["component"]:
                            comp_dic[comp.name] = comp
                            component_list.append(comp)
                    else:
                        comp_dic["root"] = merge_component(comp_dic.get("root", None), meta_data["component"])
                
                if meta_data["dependson"]:
                    for comp_name, deps in meta_data["dependson"].items():
                        if deps:
                            comp_deps = dependson.get(comp_name, [])
                            comp_deps.extend(deps)
                            dependson[comp_name] = comp_deps
                if meta_data["relationships"].get("builddepends", None):
                    for comp_name, deps in meta_data["relationships"]["builddepends"].items():
                        if deps:
                            comp_deps = builddepends.get(comp_name, [])
                            comp_deps.extend(deps)
                            builddepends[comp_name] = comp_deps
                if meta_data["relationships"].get("testdepends", None):
                    for comp_name, deps in meta_data["relationships"]["testdepends"].items():
                        if deps:
                            comp_deps = testdepends.get(comp_name, [])
                            comp_deps.extend(deps)
                            testdepends[comp_name] = comp_deps
                if meta_data["relationships"].get("devdepends", None):
                    for comp_name, deps in meta_data["relationships"]["devdepends"].items():
                        if deps:
                            comp_deps = devdepends.get(comp_name, [])
                            comp_deps.extend(deps)
                            devdepends[comp_name] = comp_deps
            
            elif ((not ".license" in file.lower()) and "license" in file.lower()):
                license_info = get_licenses(os.path.join(root, file))
                comp_license = middleware.License(
                    type="concluded",
                    spdxID=license_info.get("detected_license_expression_spdx", None),
                    name=license_info.get("detected_license_expression", None),
                )
            elif ((not ".copyright" in file.lower()) and "copyright" in file.lower()):
                comp_copyright = copyright_from_pkgfile(os.path.join(root, file))
            elif is_py_file(file):                
                dependency = pyfile_depends(os.path.join(root, file))
                remove_lst = []
                for dep in dependency:
                    if dep in dirs or (dep + ".py") in files or dep in root:
                        remove_lst.append(dep)
                for dep in remove_lst:
                    dependency.remove(dep)

                if "test" in root:
                    comp_deps = testdepends.get("root", [])
                    comp_deps.extend(dependency)
                    testdepends["root"] = comp_deps
                elif "build" in root:
                    comp_deps = builddepends.get("root", [])
                    comp_deps.extend(dependency)
                    builddepends["root"] = comp_deps
                elif "dev" in root:
                    comp_deps = devdepends.get("root", [])
                    comp_deps.extend(dependency)
                    devdepends["root"] = comp_deps
                else:
                    comp_deps = dependson.get("root", [])
                    comp_deps.extend(dependency)
                    dependson["root"] = comp_deps
                
                comp_list = analyze_pyfile_meta(os.path.join(root, file))
                if comp_list:
                    common_comp_list.extend(comp_list)
                    for i, comp_file in enumerate(comp_list):
                        if i == 0:
                            relations.append(
                                middleware.Relationship(
                                    type="CONTAINS",
                                    sourceID="root",
                                    targetID=comp_file.ID
                                )
                            )
                        else:
                            relations.append(
                                middleware.Relationship(
                                    type="CONTAINS",
                                    sourceID=comp_list[0].ID,
                                    targetID=comp_file.ID
                                )
                            )

    if comp_dic.get("root", None):
        root_comp = comp_dic["root"]
        common_comp_list.append(root_comp)
        if not root_comp.name:
            root_comp.name = path.split(os.sep)[-1]
        if not root_comp.licenses:
            root_comp.licenses = [comp_license]
        if not root_comp.copyright:
            root_comp.copyright = comp_copyright
        if not root_comp.ID:
            root_comp.ID = IDManager.get_pkgID(pkgtype = "pypi", name = comp.name)
    else:
        name = path.split(os.sep)[-1]
        root_comp = middleware.Component(
            type="Package: LIBRARY",
            name=name,
            ID=IDManager.get_pkgID(pkgtype = "pypi", name = name),
            licenses=[comp_license],
            copyright=comp_copyright,
        )
        comp_dic["root"] = root_comp
        common_comp_list.append(root_comp)
    
    for rel in relations:
        if rel.sourceID == "root":
            rel.sourceID = comp_dic["root"].ID
    
    logging.info("merge all the info...")
    if pkg_metas:
        root_comp = comp_dic["root"]
        comp_dic = {}
        comp_dic["root"] = root_comp
        comp_dic[root_comp.name] = root_comp
        component_list = []
        component_list.extend(common_comp_list)
        for pkg in pkg_metas:
            component_list.append(pkg["component"])
            relations.extend(pkg["relationships"].get("contains", []))
            comp_dic[pkg["component"].name] = pkg["component"]
        
        for pkg in pkg_metas:
            for dep_import in pkg["dependson"]:
                for pkg_name, deps in pkg2import.items():
                    if dep_import in deps:
                        comp = comp_dic.get(pkg_name, None)
                        if comp:
                            if comp.name == pkg["component"].name:
                                continue
                            logging.info(f"Add DEPENDS_ON Relationship between {pkg['component'].name} and {comp.name}")
                            relations.append(
                                middleware.Relationship(
                                    type="DEPENDS_ON",
                                    sourceID=pkg["component"].ID,
                                    targetID=comp.ID
                                )
                            )
                            break
            if pkg["relationships"].get("contains", None):
                for rel in pkg["relationships"]["contains"]:
                    relations.append(rel)

        root_deps = dependson.get("root", [])
        for dep_import in root_deps:
            if isinstance(dep_import, str):
                for pkg_name, deps in pkg2import.items():
                    if dep_import in deps:
                        comp = comp_dic.get(pkg_name, None)
                        if comp:
                            if comp.name == root_comp.name:
                                continue
                            logging.info(f"Add DEPENDS_ON Relationship between {pkg['component'].name} and {comp.name}")
                            relations.append(
                                middleware.Relationship(
                                    type="DEPENDS_ON",
                                    sourceID=root_comp.ID,
                                    targetID=comp.ID
                                )
                            )
                            break
        
        relations = merge_depends_withenv(testdepends, "TEST_DEPENDENCY_OF", relations, comp_dic, pkg2import)
        relations = merge_depends_withenv(builddepends, "BUILD_DEPENDENCY_OF", relations, comp_dic, pkg2import)
        relations = merge_depends_withenv(devdepends, "DEV_DEPENDENCY_OF", relations, comp_dic, pkg2import)
    else:
        # 文件中的所有comp，root_comp，py文件
        component_list.extend(common_comp_list)
        comp_dic, component_list, relations = merge_depends_withoutenv(dependson, "DEPENDS_ON", comp_dic, component_list, relations)
        comp_dic, component_list, relations = merge_depends_withoutenv(testdepends, "TEST_DEPENDENCY_OF", comp_dic, component_list, relations)
        comp_dic, component_list, relations = merge_depends_withoutenv(builddepends, "BUILD_DEPENDENCY_OF", comp_dic, component_list, relations)
        comp_dic, component_list, relations = merge_depends_withoutenv(devdepends, "DEV_DEPENDENCY_OF", comp_dic, component_list, relations)

        # req_pypi, 补全所有的ID, 补全purl
        for comp in component_list:
            meta = req_pypi(comp.name)
            if meta.get("declaredLicense", None):
                comp.licenses = str2license(meta["declaredLicense"])
            if meta.get("pkgChecksum", None):
                checksums = []
                if isinstance(meta["pkgChecksum"], str):
                    if ":" in meta["pkgChecksum"]:
                        alg, value = meta["pkgChecksum"].split(":")
                        checksums.append(
                            middleware.Hash(
                                alg=alg,
                                value=value
                            )
                        )
                elif isinstance(meta["pkgChecksum"], List):
                    for ck in meta["pkgChecksum"]:
                        if ":" in ck:
                            alg, value = ck.split(":")
                            checksums.append(
                                middleware.Hash(
                                    alg=alg,
                                    value=value
                                )
                            )
                comp.checksum = checksums if checksums else None
            if meta.get("pkgRef", None):
                comp.external_references = meta["pkgRef"] if meta["pkgRef"] else None
            if meta.get("homepage", None):
                comp.homepage = meta["homepage"]
            if meta.get("sourceRepo", None):
                comp.source_repo = meta["sourceRepo"] if meta["sourceRepo"] else None
            if meta.get("downloadLocation", None):
                comp.download_location = meta["downloadLocation"]
            if meta.get("originator", None):
                comp.originator = meta["originator"] if meta["originator"] else None
            
            if not comp.ID:
                comp.ID = IDManager.get_pkgID(pkgtype = "pypi", name = comp.name, version = comp.version)
            if is_valid_purl(comp.ID):
                comp.purl = comp.ID
            
    tool_purl = PackageURL(type = "github", namespace = "https://github.com/gmscofield/", name = "sbom-generator", version = "1.0").to_string()
    root_name = comp_dic["root"].name
    midware = middleware.Middleware(
        doc_ID=IDManager.get_docID(),
        doc_name=f"SBOM for {root_name}",
        doc_namespace="https://github.com/gmscofield",
        license_list_version=LICENSE_LIST_VERSION,
        timestamp=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        licenses=[
            middleware.License(
                type="declared",
                spdxID="CC0-1.0"
            )
        ],
        creator=[
            middleware.Component(
                type="Package: LIBRARY",
                name="SbomGT",
                version="1.0",
                ID=tool_purl,
                purl=tool_purl,
                originator=[middleware.Individual(type='person', name='gmscofield')],
                licenses=[middleware.License(type='declared', spdxID='MIT')],
                download_location='https://github.com/gmscofield/sbom-generator',
                source_repo='https://github.com/gmscofield/sbom-generator',
                homepage='https://github.com/gmscofield',
            )
        ],
        components=component_list,
        relationship=relations
    )
    
    if model == "middleware":
        return midware.model_dump(mode='json', by_alias=True, exclude_none=True)
    elif model == "ossbom":
        return ossbom_conversion.Middleware2Ossbom(midware).middleware2ossbom()
    elif model == "cyclonedx":
        return cdx_conversion.Middleware2Cdx(midware).middleware2cdx()
    elif model == "spdx":
        return spdx_conversion.Middleware2Spdx(midware).middleware2spdx()
    else:
        raise Exception("Unsupported model")
    
    
def output_bom(bom: dict, output_path: str) -> None:
    if output_path != "-":
        if not output_path.endswith(".json"):
            output_path = os.path.join(output_path, "sbom.json")
        head, _ = os.path.split(output_path)
        if not os.path.exists(head):
            os.makedirs(head)
        IOwriter = open(output_path, "w")
    else:
        IOwriter = sys.stdout
    
    json.dump(bom, IOwriter, indent=4)
    IOwriter = sys.stdout
    logging.info("SBOM has been generated successfully!")
    