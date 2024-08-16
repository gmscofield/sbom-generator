import os
import re
import datetime
import requests
import sys
import uuid
from packageurl import PackageURL
import cyclonedx.model.component
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model.contact import OrganizationalEntity, OrganizationalContact
from cyclonedx.output.json import JsonV1Dot6
import cyclonedx.model.bom
import cyclonedx.output
import spdx_tools

from .meta.pypi import analyze_pyproject_meta, analyze_requirements_meta, analyze_setup_meta, \
    analyze_pipfile_meta, analyze_pipfileLock_meta, analyze_pdm_meta, analyze_poetry_meta
from .meta.conda import analyze_metayaml_meta, analyze_condayml_meta
from .meta.utils import support_format, uri2name, analyze_component_meta, license_from_pkgfile, \
    copyright_from_pkgfile, pkg_meta_template, meta_template, norm_path
from .meta.val_depend import parse_pyfile, is_py_file
from ...sbomModel.universal import IDManager, Ref
from ...sbomModel.pkgInfo import PkgInfo, PkgList
from ...sbomModel.componentInfo import ComponentList, ComponentInfo
from ...sbomModel.validityInfo import ResourceValidityInfo, ValidityInfo
from ...sbomModel.relationInfo import RelationshipInfo
from ...sbomModel.ossbom import OSSBOM
from ...sbomModel.license import LicenseList


py_env = ["anaconda3", "conda3", "anaconda", "conda", "miniconda", "miniconda3", "pip3", "pip", "pypi", "pdm", "poetry", "pipfile"]

def pkgException(pkg_name, level):
    pkgID = IDManager.get_pkgID()
    meta = meta_template(level=level)
    meta["pkg"]["pkg"]["pkgName"] = pkg_name
    meta["pkg"]["pkg"]["pkgID"] = pkgID
    if level == 3:
        meta["pkg"]["pkgValid"]["resourceID"] = pkgID
    return meta


def merge_meta(meta1, meta2, level = 1):
    meta = pkg_meta_template(level)
    
    if (not meta1 or not meta1["pkg"]) and (not meta2 or not meta2["pkg"]):
        meta["pkg"] = {}
    elif not meta2 or not meta2["pkg"]:
        meta["pkg"] = meta1["pkg"]
    elif not meta1 or not meta1["pkg"]:
        meta["pkg"] = meta2["pkg"]
    else:
        meta["pkg"]["pkgName"] = meta1["pkg"]["pkgName"] if meta1["pkg"].get("pkgName", None) else meta2["pkg"].get("pkgName", None)
        meta["pkg"]["pkgID"] = IDManager.merge_pkgID(meta1["pkg"].get("pkgID", None), meta2["pkg"].get("pkgID", None))
        meta["pkg"]["version"] = meta1["pkg"].get("version", None) if meta1["pkg"].get("version", None) else meta2["pkg"].get("version", None)
        meta["pkg"]["declaredLicense"] = meta1["pkg"].get("declaredLicense", None) if meta1["pkg"].get("declaredLicense", None) else meta2["pkg"].get("declaredLicense", None)
        meta["pkg"]["pkgChecksum"] = meta1["pkg"].get("pkgChecksum", None) if meta1["pkg"].get("pkgChecksum", None) else meta2["pkg"].get("pkgChecksum", None)
        meta["pkg"]["copyright"] = meta1["pkg"].get("copyright", None) if meta1["pkg"].get("copyright", None) else meta2["pkg"].get("copyright", None)
        
        meta["pkg"]["pkgRef"] = Ref()
        if meta1["pkg"].get("pkgRef", None):
            meta["pkg"]["pkgRef"].extend(meta1["pkg"]["pkgRef"])
        if meta2["pkg"].get("pkgRef", None):
            meta["pkg"]["pkgRef"].extend(meta2["pkg"]["pkgRef"])

    if meta1 and meta2:
        meta["dependson"] = meta1.get("dependson", []) + meta2.get("dependson", [])
        meta["builddepends"] = meta1.get("builddepends", []) + meta2.get("builddepends", [])

    if level == 3:
        meta["pkgValid"]["downloadLocation"] = meta1["pkgValid"]["downloadLocation"] if meta1["pkgValid"].get("downloadLocation", None) else meta2["pkgValid"].get("downloadLocation", None)
        meta["pkgValid"]["sourceRepo"] = meta1["pkgValid"]["sourceRepo"] if meta1["pkgValid"].get("sourceRepo", None) else meta2["pkgValid"].get("sourceRepo", None)
        meta["pkgValid"]["homepage"] = meta1["pkgValid"]["homepage"] if meta1["pkgValid"].get("homepage", None) else meta2["pkgValid"].get("homepage", None)
        meta["pkgValid"]["supplier"] = meta1["pkgValid"]["supplier"] if meta1["pkgValid"].get("supplier", None) else meta2["pkgValid"].get("supplier", None)
        meta["pkgValid"]["originator"] = meta1["pkgValid"]["originator"] if meta1["pkgValid"].get("originator", None) else meta2["pkgValid"].get("originator", None)
        meta["pkgValid"]["resourceID"] = meta["pkg"]["pkgID"]
    return meta


def req_pypi(pkg_name, level):
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
        all_meta = meta_template(level=level)
        meta = all_meta["pkg"]
        meta["pkg"]["pkgName"] = res.get("name", pkg_name)
        meta["pkg"]["version"] = res.get("version", None)
        meta["pkg"]["declaredLicense"] = res.get("license", None)
        meta["pkg"]["pkgChecksum"] = res.get("checksum", None)
        meta["pkg"]["pkgRef"] = Ref()
        doc = res.get("docs_url", None)
        if doc:
            meta["pkg"]["pkgRef"].insert(name = uri2name(doc), docURI = doc)
        sourceRepo = ""
        pjurls = res.get("project_urls", {})
        if pjurls:
            for key, value in pjurls.items():
                if "source" in key or "Source" in key or "repo" in key or "Repo" in key or "vcs" in key or "VCS" in key:
                    sourceRepo = value
                    break
        meta["pkg"]["pkgID"] = IDManager.get_pkgID(pkgtype = "pypi", name = meta["pkg"]["pkgName"], version = meta["pkg"]["version"], url = sourceRepo)
        if level == 3:
            meta["pkgValid"] = {
                "resourceID": meta["pkg"]["pkgID"], 
                "downloadLocation": res.get("download_url", None), 
                "sourceRepo": sourceRepo, 
                "homepage": res.get("home_page", None),
                "supplier": "PyPI (admin@pypi.org)"
            }
            author = res.get("author", None)
            author_mail = res.get("author_email", None)
            if author or author_mail:
                if author and author_mail:
                    originator = author + " (" + author_mail + ")"
                elif author:
                    originator = author
                else:
                    originator = author_mail
                meta["pkgValid"]["originator"] = originator

    if not all_meta:
        all_meta = pkgException(pkg_name, level)
    return all_meta


def format2func(format):
    func_dict = {
        "conda.yml": analyze_condayml_meta,
        "meta.yaml": analyze_metayaml_meta,
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
    return func_dict[format]


def analyze_all_meta(path, level = 1):
    paths = os.walk(path)
    key_words = ["test", "Test", "alias", "Alias", "doc", "Doc", "sample", "Sample", "ci", ".git"]
    pkg_meta = pkg_meta_template(level)
    all_license = []
    valid_dependson = []
    meta = meta_template(level)
    for root, dirs, files in paths:
        flag = False
        for word in key_words:
            if word in root:
                flag = True
        if flag:
            continue
        # if "pyproject.toml" in files:
        #     pymeta = analyze_pyproject_meta(os.path.join(root, "pyproject.toml"), level)
        #     meta = merge_meta(meta, pymeta, level)
        #     print(os.path.join(root, "pyproject.toml"))
        # elif "requirements.txt" in files:
        #     reqmeta = analyze_requirements_meta(os.path.join(root, "requirements.txt"), level)
        #     meta = merge_meta(meta, reqmeta, level)
        # elif "setup.py" in files:
        #     meta = analyze_setup_meta(os.path.join(root, "setup.py"), level)
        # elif "meta.yaml" in files:
        #     meta = analyze_metayaml_meta(os.path.join(root, "meta.yaml"), level)
        
        for file in files:
            if file in support_format:
                meta_data = format2func(file)(os.path.join(root, file), level)
                pkg_meta = merge_meta(pkg_meta, meta_data, level)
            elif (not ".license" in file.lower() and "license" in file.lower()) or (not ".copyright" in file.lower() and "copyright" in file.lower()):
                spdx_id, license_list = license_from_pkgfile(os.path.join(root, file))
                if spdx_id:
                    pkg_meta["pkg"]["declaredLicense"] = spdx_id
                if license_list:
                    all_license.extend(license_list)

                cr = copyright_from_pkgfile(os.path.join(root, file))
                if cr:
                    pkg_meta["pkg"]["copyright"] = cr

            if level >= 2:
                componentList_meta, license_list = analyze_component_meta(os.path.join(root, file), pkg_meta["pkg"].get("declaredLicense", None), level)
                if componentList_meta:
                    meta["component"].extend(componentList_meta)
                if license_list:
                    all_license.extend(license_list)
            
            abspath = os.path.join(root, file)
            if is_py_file(abspath):
                dependency = parse_pyfile(abspath)
                remove_lst = []
                for dep in dependency:
                    d = list(dep.keys())[0]
                    if d in dirs or d in files:
                        remove_lst.append(dep)
                for d in remove_lst:
                    dependency.remove(d)
                valid_dependson += dependency

    pkg_meta["dependson"] += valid_dependson
    # 最后必须要整合pkg信息、component信息等汇成总信息传递回去
    meta["pkg"] = pkg_meta
    meta["license"] = all_license
    return meta


def analyze_meta(path, level = 1):
    meta = analyze_all_meta(path, level)
    pkg = meta["pkg"]
    if not pkg["pkg"].get("pkgName", None) or not pkg["pkg"].get("pkgID", None):
        pkg = merge_meta(pkg, pkgException(path.split(os.sep)[-1], level), level)
    if level == 3:
        name = pkg["pkg"]["pkgName"]
        pypi_pkg = req_pypi(name, level)
        pkg = merge_meta(pkg, pypi_pkg, level)
    meta["pkg"] = pkg
    return meta


def meta2sbomInfo(meta, level = 1):
    # "pkg": None, "component": [] if level >= 2 else None, "license": None
    if meta:
        pkg_meta = meta["pkg"]
        pkgInfo = PkgInfo(pkgName = pkg_meta["pkg"]["pkgName"], 
                          pkgID = pkg_meta["pkg"]["pkgID"],
                          version = pkg_meta["pkg"].get("version", None),
                          pkgChecksum = pkg_meta["pkg"].get("pkgChecksum", None),
                          declaredLicense = pkg_meta["pkg"].get("declaredLicense", None),
                          copyright= pkg_meta["pkg"].get("copyright", None),
                          pkgRef = pkg_meta["pkg"].get("pkgRef", Ref()))
        
        rsInfo = []
        if level == 3:
            rsInfo.append(
                ResourceValidityInfo(
                    resourceID = pkg_meta["pkgValid"].get("resourceID", None), 
                    downloadLocation = pkg_meta["pkgValid"].get("downloadLocation", None), 
                    sourceRepo = pkg_meta["pkgValid"].get("sourceRepo", None), 
                    homepage = pkg_meta["pkgValid"].get("homepage", None), 
                    supplier = pkg_meta["pkgValid"].get("supplier", None), 
                    originator = pkg_meta["pkgValid"].get("originator", None)
                )
            )
        
        componentList = []
        if level >= 2:
            component_meta = meta["component"]
            for component in component_meta:
                componentList.append(
                    ComponentInfo(
                        componentType = component["component"]["componentType"],
                        componentName = component["component"]["componentName"],
                        componentID = component["component"]["componentID"],
                        location = component["component"]["componentLocation"],
                        componentChecksum = component["component"].get("componentChecksum", None),
                        copyright = component["component"].get("copyright", None),
                        declaredLicense = component["component"].get("componentLicense", None),
                        componentRef = component["component"].get("componentRef", Ref())
                    )
                )
                if level == 3:
                    rsInfo.append(
                        ResourceValidityInfo(
                            resourceID = component["componentValid"].get("componentID", None),
                            downloadLocation = component["componentValid"].get("downloadLocation", None),
                            sourceRepo = component["componentValid"].get("sourceRepo", None),
                            homepage = component["componentValid"].get("homepage", None),
                            supplier = component["componentValid"].get("supplier", None),
                            originator = component["componentValid"].get("originator", None)
                        )
                    )
            
        return [pkgInfo, rsInfo, componentList, meta["license"]]
    else:
        raise Exception("meta data not found")


def search_meta(name, level = 1):
    path_list = sys.path
    cur_dir = os.path.dirname(__file__)
    meta = meta_template(level)
    for path in path_list:
        if cur_dir.startswith(path) or not os.path.isdir(path):
            continue
        all_path = os.listdir(path)
        for p in all_path:
            # TODO
            if name == p:
                meta_path = os.path.join(path, p)
                if os.path.isdir(meta_path):
                    meta = analyze_meta(meta_path, level)
                    return meta
    if level == 3:
        meta["pkg"] = req_pypi(name, level)
    else:
        meta["pkg"] = pkgException(name, level)
    # print("search_meta", meta)
    return meta


def merge_special_depends(depend, version, sbomInfoList):
    # self.pkgName = pkgName
    # self.pkgID = pkgID
    # self.pkgVersion = version
    if not sbomInfoList["pkgList"].is_existPkg(depend):
        dependID = IDManager.get_pkgID(pkgtype = "pypi", name = depend)
        pkgInfo = PkgInfo(pkgName = depend, pkgID = dependID, version = version)
        sbomInfoList["pkgList"].insert(pkgInfo)
        return sbomInfoList, dependID
    else:
        return sbomInfoList, None
    

def merge_sbomInfo(metaInfo, sbomInfoList, level):
    pkgInfo, rsInfo, cpList, lcList = metaInfo[0], metaInfo[1], metaInfo[2], metaInfo[3]
    if not sbomInfoList["pkgList"].is_existPkg(pkgInfo.pkgName):
        sbomInfoList["pkgList"].insert(pkgInfo)
        if level == 3:
            sbomInfoList["validityInfo"].insert(rsInfo[0])
    
    if level >= 2:
        for i in range(len(cpList)):
            if not sbomInfoList["componentList"].is_existComponent(cpList[i].componentName):
                sbomInfoList["componentList"].insert(cpList[i])
                if level == 3:
                    sbomInfoList["validityInfo"].insert(rsInfo[i + 1])
    
    for lc in lcList:
        if not sbomInfoList["licenseList"].is_existLicense(lc):
            sbomInfoList["licenseList"].insert(lc)
    
    # print(sbomInfoList["pkgList"].pkgList)
    return sbomInfoList


def buildBom(path, level = 1, tree = False):
    pkgList = PkgList()
    componentList = ComponentList()
    validityInfo = ValidityInfo()
    relationInfo = RelationshipInfo()
    licenseList = LicenseList()

    sbomInfoList = {}
    sbomInfoList["pkgList"] = pkgList
    sbomInfoList["componentList"] = componentList
    sbomInfoList["validityInfo"] = validityInfo
    sbomInfoList["licenseList"] = licenseList

    meta = analyze_meta(path, level)
    metaInfo = meta2sbomInfo(meta, level)
    sbomInfoList = merge_sbomInfo(metaInfo, sbomInfoList, level)
    # print(sbomInfoList["pkgList"].cnt, sbomInfoList["componentList"].componentList)
    ctID = ""
    for ct in sbomInfoList["componentList"].componentList:    
        if ct.componentType == "FILE":
            ctID = ct.componentID
            relationInfo.insert("Contain", meta["pkg"]["pkg"]["pkgID"], ct.componentID)
        elif ct.componentType == "SNIPPET":
            if ctID:
                relationInfo.insert("Contain", ctID, ct.componentID)
            else:
                relationInfo.insert("Contain", meta["pkg"]["pkg"]["pkgID"], ct.componentID)
    
    pkg_meta = meta["pkg"]
    builddepends = pkg_meta.get("builddepends", None)
    if builddepends:
        for builddep in builddepends:
            build, version = list(builddep.items())[0]
            if build in py_env:
                continue
            exist_pkg = pkgList.is_existPkg(build)
            if exist_pkg:
                relationInfo.insert("BuildDepends", pkg_meta["pkg"]["pkgID"], exist_pkg.pkgID)
                continue
            if version:
                sbomInfoList, dependID = merge_special_depends(build, version, sbomInfoList)
                if dependID:
                    relationInfo.insert("BuildDepends", pkg_meta["pkg"]["pkgID"], dependID)
                continue
            
            build_meta = search_meta(build, level = 1)
            build_metaInfo = meta2sbomInfo(build_meta, level)
            sbomInfoList = merge_sbomInfo(build_metaInfo, sbomInfoList, level)
            relationInfo.insert("BuildDepends", pkg_meta["pkg"]["pkgID"], build_meta["pkg"]["pkg"]["pkgID"])

    # builddepends, dependson
    # dependson = list(set(pkg_meta.get("dependson", {}).keys()))
    dependson = pkg_meta.get("dependson", [])
    # print(dependson)
    num = sbomInfoList["componentList"].cnt
    que = []
    if dependson:
        que.append({pkg_meta["pkg"]["pkgID"]: dependson})
        while que:
            top = que.pop()
            pkgID, depends = list(top.items())[0]
            # print("depends", depends)
            if not depends:
                continue
            for item in depends:
                depend, (version, import_name) = list(item.items())[0]
                if depend in py_env:
                    continue
                exist_pkg = pkgList.is_existPkg(depend)
                if exist_pkg:
                    relationInfo.insert("DependsOn", pkgID, exist_pkg.pkgID)
                    continue
                # if version:
                #    sbomInfoList, dependID = merge_special_depends(depend, version, sbomInfoList)
                #    if dependID:
                #        relationInfo.insert("DependsOn", pkgID, dependID)
                #    continue
                print(import_name, depend)
                depend_meta = search_meta(import_name if import_name else depend, level)
                # if pkgList.is_existPkg(depend_meta["pkg"]["pkg"]["pkgName"]) or IDManager.is_existID("rsID", depend_meta["pkg"]["pkg"]["pkgID"]):
                #     relationInfo.insert("DependsOn", pkgID, depend_meta["pkg"]["pkg"]["pkgID"])
                #     continue
                depend_meta["pkg"]["pkg"]["pkgName"] = depend
                depend_metaInfo = meta2sbomInfo(depend_meta, level)
                sbomInfoList = merge_sbomInfo(depend_metaInfo, sbomInfoList, level)
                relationInfo.insert("DependsOn", pkgID, depend_meta["pkg"]["pkg"]["pkgID"])
                
                while num < sbomInfoList["componentList"].cnt:
                    ct = sbomInfoList["componentList"].componentList[num]
                    if ct.componentType == "FILE":
                        ctID = ct.componentID
                        relationInfo.insert("Contain", depend_meta["pkg"]["pkg"]["pkgID"], ct.componentID)
                    elif ct.componentType == "SNIPPET":
                        if ctID:
                            relationInfo.insert("Contain", ctID, ct.componentID)
                        else:
                            relationInfo.insert("Contain", depend_meta["pkg"]["pkg"]["pkgID"], ct.componentID)
                    num += 1
                    print(ctID)
                    
                
                if tree:
                    print(depend_meta["pkg"]["pkg"]["pkgName"])
                    que.append({depend_meta["pkg"]["pkg"]["pkgID"]: depend_meta["pkg"].get("dependson", [])})
                    print({depend_meta["pkg"]["pkg"]["pkgID"]: depend_meta["pkg"].get("dependson", [])})
    
    for comp in sbomInfoList["componentList"].componentList:
        if comp.componentType == "FILE":
            comp.componentName = norm_path(path, comp.componentName)
            comp.componentLocation = comp.componentID + "<L>" + comp.componentName
        elif comp.componentType == "SNIPPET":
            compls = comp.componentName.split("in ")
            comp.componentName = compls[0] + "in " + norm_path(path, compls[1])
    
    bom = OSSBOM(
        level = level, 
        pkgList = sbomInfoList["pkgList"], 
        componentList = sbomInfoList["componentList"],
        validityInfo = sbomInfoList["validityInfo"], 
        licenseList = sbomInfoList["licenseList"],
        relashionshipInfo = relationInfo
    )
    return bom


def is_valid_purl(purl):
    purl_regex = re.compile(
        r'^pkg:(?P<type>[^/]+)/(?:(?P<namespace>[^/]+)/)?(?P<name>[^@]+)(?:@(?P<version>[^?]+))?(?:\?(?P<qualifiers>[^#]+))?(?:#(?P<subpath>.*))?$'
    )
    match = purl_regex.match(purl)
    return match is not None


def makeBOM(bomInfo, filepath = "-", fileformat = "txt", model = "ossbom"):
    if filepath != "-":
        if not filepath.endswith("." + fileformat):
            filepath = os.path.join(filepath, model + "."+ fileformat)
        head, tail = os.path.split(filepath)
        if not os.path.exists(head):
            os.makedirs(head)
        IOwriter = open(filepath, "w")
    else:
        IOwriter = sys.stdout
    
    if model == "ossbom":
        format2func = {
            "txt": bomInfo.toTXT,
            "json": bomInfo.toJSON,
            "yaml": bomInfo.toYAML
        }
        
        format2func[fileformat](IOwriter)
        
    else:
        bomDict = bomInfo.toDict()
        all_pkg_info = {}
        all_ct_info = {}
        for pkginfo in bomDict.get("PackageInformation", []):
            info = {}
            info.update(pkginfo)
            for valinfo in bomDict["ValidityInformation"].get("ResourceValidityInfo", []):
                print(valinfo)
                if pkginfo["PackageID"] == valinfo["ResourceID"]:
                    info.update(valinfo)
                    break
            all_pkg_info[pkginfo["PackageID"]] = info

        for ctinfo in bomDict.get("ComponentInformation", []):
            info = {}
            info.update(ctinfo)
            for valinfo in bomDict["ValidityInformation"].get("ResourceValidityInfo", []):
                if ctinfo["ComponentID"] == valinfo["ResourceID"]:
                    info.update(valinfo)
                    break
            all_ct_info[ctinfo["ComponentID"]] = info
        
        if model == "spdx":
            pass
        elif model == "cyclonedx":
            bom = cyclonedx.model.bom.Bom()
            lc_factory = LicenseFactory()
            # document, package, component, validity, relationship, license, annotation
            pkgDict = {}
            ctDict = {}
            for ID, info in all_pkg_info.items():
                component_hashes = []
                component_properties = []
                component_references = []
                
                for ct_ref in info.get("PackageRef", []):
                    component_references.append(cyclonedx.model.ExternalReference(type=cyclonedx.model.ExternalReferenceType.WEBSITE, 
                                                                                url=ct_ref["DocumentURI"], 
                                                                                comment=ct_ref["Name"])
                    )
                
                for ct_checksum in info.get("PackageChecksum", []):
                    try:
                        component_hashes.append(
                            cyclonedx.model.component.HashType.from_composite_str(ct_checksum["Algorithm"] + ":" + ct_checksum["Checksum"])
                        )
                    except:
                        component_properties.append(cyclonedx.model.Property(name=(ct_checksum["Algorithm"]), value=ct_checksum["Checksum"]))
                                
                if info.get("DownloadLocation", None):
                    component_properties.append(cyclonedx.model.Property(name="DownloadLocation", value=info["DownloadLocation"])) 
                if info.get("SourceRepository", None):
                    component_properties.append(cyclonedx.model.Property(name="SourceRepository", value=info["SourceRepository"]))
                if info.get("HomePage", None):
                    component_properties.append(cyclonedx.model.Property(name="HomePage", value=info["HomePage"]))
                if info.get("ReleaseTime", None):
                    component_properties.append(cyclonedx.model.Property(name="ReleaseTime", value=info["ReleaseTime"]))
                if info.get("BuiltTime", None):
                    component_properties.append(cyclonedx.model.Property(name="BuiltTime", value=info["BuiltTime"]))
                if info.get("ValidUntilTime", None):
                    component_properties.append(cyclonedx.model.Property(name="ValidUntilTime", value=info["ValidUntilTime"]))
                
                cdx_component = cyclonedx.model.component.Component(
                    name=info["PackageName"],
                    type=cyclonedx.model.component.ComponentType.LIBRARY,
                    version=info.get("PackageVersion", None),
                    bom_ref=ID,
                    supplier=OrganizationalEntity(name=info["Supplier"]) if info.get("Supplier", None) else None,
                    publisher=None,
                    group=None,
                    description=None,
                    scope=None,
                    hashes=component_hashes,
                    licenses=[lc_factory.make_from_string(info["DeclaredLicense"])] if info.get("DeclaredLicense", None) else None,
                    copyright=info.get("Copyright", None),
                    purl=PackageURL.from_string(ID) if is_valid_purl(ID) else None,
                    external_references=component_references,
                    properties=component_properties,
                    release_notes=None,
                    cpe=None,
                    swid=None,
                    pedigree=None,
                    components=None,
                    evidence=None,
                    modified=False,
                    manufacturer=OrganizationalContact(name=info["Originator"]) if info.get("Originator", None) else None,
                    authors=None,
                    omnibor_ids=None,
                    swhids=None,
                    crypto_properties=None,
                    tags=None,
                    author=None,
                )
                pkgDict[ID] = cdx_component
            
            for ID, info in all_ct_info.items():
                component_hashes = []
                component_properties = []
                component_references = []
                
                for ct_ref in info.get("ComponentRef", []):
                    component_references.append(cyclonedx.model.ExternalReference(type=cyclonedx.model.ExternalReferenceType.WEBSITE, 
                                                                                url=ct_ref["DocumentURI"], 
                                                                                comment=ct_ref["Name"])
                    )
                
                for ct_checksum in info.get("ComponentChecksum", []):
                    try:
                        component_hashes.append(
                            cyclonedx.model.component.HashType.from_composite_str(ct_checksum["Algorithm"] + ":" + ct_checksum["Checksum"])
                        )
                    except:
                        component_properties.append(cyclonedx.model.Property(name=(ct_checksum["Algorithm"]), value=ct_checksum["Checksum"]))
                
                if info.get("ComponentLocation", None):
                    component_properties.append(cyclonedx.model.Property(name="ComponentLocation", value=info["ComponentLocation"]))
                if info.get("ComponentType", None):
                    component_properties.append(cyclonedx.model.Property(name="ComponentType", value=info["ComponentType"]))
                if info.get("DownloadLocation", None):
                    component_properties.append(cyclonedx.model.Property(name="DownloadLocation", value=info["DownloadLocation"])) 
                if info.get("SourceRepository", None):
                    component_properties.append(cyclonedx.model.Property(name="SourceRepository", value=info["SourceRepository"]))
                if info.get("HomePage", None):
                    component_properties.append(cyclonedx.model.Property(name="HomePage", value=info["HomePage"]))
                if info.get("ReleaseTime", None):
                    component_properties.append(cyclonedx.model.Property(name="ReleaseTime", value=info["ReleaseTime"]))
                if info.get("BuiltTime", None):
                    component_properties.append(cyclonedx.model.Property(name="BuiltTime", value=info["BuiltTime"]))
                if info.get("ValidUntilTime", None):
                    component_properties.append(cyclonedx.model.Property(name="ValidUntilTime", value=info["ValidUntilTime"]))
                
                cdx_component = cyclonedx.model.component.Component(
                    name=info["ComponentName"],
                    type=cyclonedx.model.component.ComponentType.FILE,
                    version=None,
                    bom_ref=ID,
                    supplier=OrganizationalEntity(name=info.get("Supplier", None)),
                    publisher=None,
                    group=None,
                    description=None,
                    scope=None,
                    hashes=component_hashes,
                    licenses=lc_factory.make_from_string(info.get("DeclaredLicense", None)),
                    copyright=info.get("Copyright", None),
                    purl=PackageURL.from_string(ID) if is_valid_purl(ID) else None,
                    external_references=component_references,
                    properties=component_properties,
                    release_notes=None,
                    cpe=None,
                    swid=None,
                    pedigree=None,
                    components=None,
                    evidence=None,
                    modified=False,
                    manufacturer=OrganizationalContact(name=info.get("Originator", None)),
                    authors=None,
                    omnibor_ids=None,
                    swhids=None,
                    crypto_properties=None,
                    tags=None,
                    author=None,
                )
                ctDict[ID] = cdx_component
            
            bom_properties = []
            for relation in bomDict["RelationshipInformation"]:
                ID = relation["ResourceID"]
                source_ct = pkgDict.get(ID, None) or ctDict.get(ID, None)
                if relation.get("Contain", None):
                    source_ct.components.add([ctDict[relation["Contain"]]])
                elif relation.get("DependsOn", None):
                    bom.register_dependency(source_ct, [pkgDict[relation["DependsOn"]]])
                elif relation.get("BuildDepends", None):
                    bom_properties.append(cyclonedx.model.Property(name=ID + "-BuildDepends", value=relation["BuildDepends"]))
            
            num = 0
            for lc in bomDict.get("OtherLicensingInformation", []):
                num += 1
                bom_properties.append(cyclonedx.model.Property(name=f"Other Licenses {num} - LicenseID", value=lc["LicenseID"]))
                bom_properties.append(cyclonedx.model.Property(name=f"Other Licenses {num} - LicenseName", value=lc["LicenseName"]))
                bom_properties.append(cyclonedx.model.Property(name=f"Other Licenses {num} - LicenseText", value=lc["LicenseText"]))
                if lc.get("LicenseChecksum", None):
                    bom_properties.append(cyclonedx.model.Property(name=f"Other Licenses {num} - LicenseChecksum", value=lc["LicenseChecksum"]))
                if lc.get("LicenseRef", None):
                    lcRef = lc["LicenseRef"]
                    for ref in lcRef:
                        bom_properties.append(cyclonedx.model.Property(name=f"Other Licenses {num} - LicenseReference - {list(ref.keys())[0]}", value=list(ref.values())[0]))

            num = 0
            for anno in bomDict.get("Annotation", []):
                num += 1
                bom_properties.append(cyclonedx.model.Property(name=f"Annotation {num} - ID", value=anno["AnnotationID"]))
                bom_properties.append(cyclonedx.model.Property(name=f"Annotation {num} - Annotator", value=anno["Annotator"]))
                bom_properties.append(cyclonedx.model.Property(name=f"Annotation {num} - AnnotationTime", value=anno["AnnotationTime"]))
                bom_properties.append(cyclonedx.model.Property(name=f"Annotation {num} - AnnotationText", value=anno["AnnotationText"]))
            
            num = 0
            for ct in pkgDict.values():
                if num == 0:
                    bom.metadata.component = ct
                elif num > 0:
                    bom.components.add(ct)
                num += 1
            
            bom.serial_number = uuid.UUID(bomDict["DocumentInformation"]["DocumentID"])
            document_Ref = []
            for docRef in bomDict["DocumentInformation"].get("DocumentRef", []):
                document_Ref.append(cyclonedx.model.ExternalReference(type=cyclonedx.model.ExternalReferenceType.WEBSITE, 
                                                                                url=docRef["DocumentURI"], 
                                                                                comment=docRef["Name"])
                )
            
            bom.external_references = document_Ref
            bom.properties = bom_properties
            bom.metadata.tools = [cyclonedx.model.Tool(name = "SbomGT", version = "1.0")]
            bom.metadata.properties = [
                cyclonedx.model.Property(name="LicenseListVersion", value=bomDict["ValidityInformation"]["LicenseListVersion"]), 
                cyclonedx.model.Property(name="DocumentLicense", value="CC0-1.0"),
            ]
            bom.metadata.timestamp = datetime.datetime.strptime(bomDict["ValidityInformation"]["DocumentCreationTime"], "%Y-%m-%dT%H:%M:%SZ")
            
            json_outputter = JsonV1Dot6(bom)
            serialized_json = json_outputter.output_as_string(indent=4)
            IOwriter.write(serialized_json)
            # print(serialized_json)
            
        else:
            raise Exception("Unsupported SBOM model")
    
    if filepath != "-":
        bomInfo.toHash(filepath)
    if not ".json" in filepath:
        file = open(os.path.join(os.path.dirname(filepath), model, ".json"), "w")
        bomInfo.toJSON(file)
        file.close()