import os
import tempfile
import hashlib
import ast
from scancode_toolkit.src.scancode.api import get_licenses, get_copyrights, get_file_info
from .val_depend import get_imports
from ..analyzeSbom import py_env
from ....sbomModel.license import License
from ....sbomModel.universal import IDManager, Ref


algoList = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", 
            "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", 
            "BLAKE2b-512", "BLAKE3", "MD2", "MD4", "MD5", "MD6", "ADLER32"]

support_format = ["conda.yml", "meta.yaml", "pyproject.toml", "setup.py", "requirements.txt", 
                "Pipfile", "Pipfile.lock", "poetry.lock", "pdm.lock"]


def pkg_meta_template(level = 1):
    return {
        "pkg": {
            "pkgName": None, 
            "pkgID": None,
            "version": None,
            "declaredLicense": [],
            "pkgChecksum": [],
            "copyright": None,
            "pkgRef": Ref(),
        }, 
        "dependson": [], 
        "builddepends": [], 
        "pkgValid": {
            "downloadLocation": None,
            "sourceRepo": None, 
            "homepage": None,
            "supplier": None,
            "originator": None,
            "resourceID": None,
        } if level == 3 else None
    }


def component_meta_template(level = 2):
    return {
        "component": {
            "componentType": None,
            "componentName": None,
            "componentID": None,
            "componentLocation": None, 
            "componentLicense": None,
            "copyright": None,
            "componentChecksum": None,
        }, 
        "componentValid": {
            "componentID": None,
            "downloadLocation": None,
            "sourceRepo": None, 
            "homepage": None,
            "supplier": None,
            "originator": None,
        } if level == 3 else None
    }


def meta_template(level = 1):
    return {
        "pkg": None, "component": [] if level >= 2 else None, "license": []
    }


def uri2name(uri):
    if uri:
        return uri.split("//")[-1].removeprefix("github.com/").rstrip("/")
    else:
        return None


def name_email_string(name, email):
    if name and email:
        return name + " (" + email + ")"
    elif name:
        return name
    elif email:
        return email
    else:
        return None


def parse_depend(depend):
    depend = depend.replace(" ", "")
    for i in range(len(depend)):
        if depend[i] in ('<', '>', '=', '!', '~', '^', '*', '(', ')', ':'):
            return {depend[:i]: (depend[i:], get_imports(depend[:i]))}            
    return {depend: (None, get_imports(depend))}


def norm_path(input_path, path):
    path = os.path.normpath(path)
    input_path = os.path.normpath(input_path)
    if input_path in path:
        path = path.replace(input_path.rstrip("/").rstrip("\\"), ".")
    else:
        pathls = path.split(os.sep)
        for i in range(len(pathls)):
            if pathls[i] in py_env:
                path = os.path.join(*pathls[i:])
    return path


def scancode2licenseList(license_info):
    algo = hashlib.sha256()
    not_license = ["def", "+" ,"-", "="]
    license_list = []
    for lc in license_info.get("license_detections", []):
        if not lc["license_expression_spdx"]:
            continue
        if not "LicenseRef-" in lc["license_expression_spdx"] or "unknown" in lc["license_expression_spdx"]:
            continue
        text = ""
        lc_ref = Ref()
        for match in lc["matches"]:
            flag = False
            for nlc in not_license:
                if nlc in text:
                    flag = True
                    break
            if flag:
                continue
            text += match["matched_text"]
            lc_ref.insert(name = uri2name(match["rule_url"]), docURI = match["rule_url"])
        
        algo.update(text.encode(encoding='UTF-8'))
        lc_checksum = algo.hexdigest()

        cur_lc = License(
            licenseID = lc["identifier"], 
            licenseName = lc["license_expression_spdx"], 
            licenseText=text, 
            checksum=lc_checksum, 
            licenseRef=lc_ref
        )
        license_list.append(cur_lc)
    return license_list


def license_from_pkgfile(path):
    if not os.path.isfile(path):
        with tempfile.NamedTemporaryFile(delete = False) as temp_file:
            temp_file.write(path.encode('utf-8'))
        real_path = temp_file.name
    else:
        real_path = path
    
    license_info = get_licenses(real_path, include_text = True, unknown_licenses=True)
    spdx_id = license_info.get("detected_license_expression_spdx", None)
    license_list = scancode2licenseList(license_info)

    if not os.path.isfile(path):
        temp_file.close()
        os.remove(real_path)
    
    return spdx_id, license_list


def copyright_from_pkgfile(path):
    cr = get_copyrights(path).get("copyrights", [])
    if cr:
        all_cr = ""
        for line in cr:
            onecr = line.get("copyright", None)
            if onecr:
                onecr += "\n"
            all_cr += onecr
        return all_cr
    else:
        return None


def get_snippet_scope(path):
    byteline_start_pos = 1
    f = open(path, "rb")
    content = f.read()
    if not "copyright".encode("utf-8") in content and not "COPYRIGHT".encode("utf-8") in content and \
         not "license".encode("utf-8") in content and not "LICENSE".encode("utf-8") in content and not "License".encode("utf-8") in content:
        return None
    
    line_startbyte = []

    f.seek(0)
    cnt = -1
    for line in f:
        cnt += 1
        line_startbyte.append(byteline_start_pos)
        byteline_start_pos += len(line)
    f.close()

    try:
        tree = ast.parse(content)
    except:
        return None
    
    snippet_scope = []
    file_start_line = len(content)
    file_end_line = 0
    file_start_byte = len(content)
    file_end_byte = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            name = node.name
            start_line = node.lineno
            end_line = node.end_lineno
            start_byte = line_startbyte[start_line - 1]
            end_byte = line_startbyte[min(end_line, cnt)] - 1
            text = content[start_byte - 1:end_byte]
            snippet_scope.append((name, start_line, end_line, start_byte, end_byte, text))
            if start_line < file_start_line:
                file_start_line = start_line
            if start_byte < file_start_byte:
                file_start_byte = start_byte
            if end_line > file_end_line:
                file_end_line = end_line
            if end_byte > file_end_byte:
                file_end_byte = end_byte
    if file_start_line == 1:
        snippet_scope.append(("FILE_START", -1, -1, -1, -1, -1))
    else:
        snippet_scope.append(("FILE_START", 1, file_start_line - 1, 1, file_start_byte - 1, -1))
    if file_end_line == cnt + 1:
        snippet_scope.append(("FILE_END", -1, -1, -1, -1, -1))
    else:
        snippet_scope.append(("FILE_END", file_end_line + 1, cnt + 1, file_end_byte + 1, len(content), -1))
    return snippet_scope


def get_component_loc(snippet_scope, lineno):
    min_line = 0
    min_snippet = None
    for snippet in snippet_scope:
        if snippet[1] <= lineno and snippet[2] >= lineno and min_line <= snippet[1]:
            min_line = snippet[1]
            min_snippet = snippet
    return min_snippet


def analyze_component_meta(path, pkg_license, level = 2):
    snippet_scope = get_snippet_scope(path)
    if not snippet_scope:
        return None, None

    component_list = []
    license_info = get_licenses(path, include_text = True, unknown_licenses=True)
    file_spdx_id = license_info.get("detected_license_expression_spdx", "")
    if not file_spdx_id or file_spdx_id == pkg_license:
        return None, None
    file_info = get_file_info(path)
    cr_info = get_copyrights(path)

    meta = component_meta_template(level)
    meta["component"]["componentType"] = "FILE"
    meta["component"]["componentName"] = path
    fileID = IDManager.get_componentID()
    meta["component"]["componentID"] = fileID
    meta["component"]["componentLocation"] = fileID + "<L>" + path
    meta["component"]["componentLicense"] = file_spdx_id
    meta["component"]["componentChecksum"] = []
    if file_info.get("sha1", None):
        meta["component"]["componentChecksum"].append({"Algorithm": "SHA1", "Checksum": file_info["sha1"]})
    if file_info.get("md5", None):
        meta["component"]["componentChecksum"].append({"Algorithm": "MD5", "Checksum": file_info["md5"]})
    if file_info.get("sha256", None):
        meta["component"]["componentChecksum"].append({"Algorithm": "SHA256", "Checksum": file_info["sha256"]})
    
    all_cr = cr_info.get("copyrights", [])
    all_holder = cr_info.get("holders", [])
    file_copyright = ""
    snippet_cr_info = {}
    snippet_holder_info = {}
    for cr in all_cr:
        snippet = get_component_loc(snippet_scope, cr["start_line"])
        if not snippet:
            continue
        if snippet[0] == "FILE_START" or snippet[0] == "FILE_END":
            file_copyright += cr["copyright"]
        else:
            if cr["copyright"] == file_copyright:
                continue
            if not snippet in snippet_cr_info:
                snippet_cr_info[snippet] = cr["copyright"]
            else:
                snippet_cr_info[snippet] += cr["copyright"]
        
        if level == 3:
            for holder in all_holder:
                if holder["start_line"] == cr["start_line"]:
                    snippet_holder_info[snippet] = holder["holder"]

    meta["component"]["copyright"] = file_copyright    
    component_list.append(meta)

    detect_licenses = license_info.get("license_detections", [])
    snippet_license_info = {}
    for lc in detect_licenses:
        if not lc["license_expression_spdx"]:
            continue
        snippet = get_component_loc(snippet_scope, lc["matches"][0]["start_line"])
        if not snippet:
            continue
        if not snippet[0] == "FILE_START" and not snippet[0] == "FILE_END":
            if not lc["license_expression_spdx"] == file_spdx_id:
                if not snippet in snippet_license_info:
                    snippet_license_info[snippet] = lc["license_expression_spdx"]
                else:
                    snippet_license_info[snippet] += " AND "
                    snippet_license_info[snippet] += lc["license_expression_spdx"]

        if not "LicenseRef-" in lc["license_expression_spdx"] or "unknown" in lc["license_expression_spdx"]:
            continue

        
    license_list = scancode2licenseList(license_info)

    cnt = 0
    algo_md5 = hashlib.md5()
    algo_sha1 = hashlib.sha1()
    algo_sha256 = hashlib.sha256()
    for snippet in snippet_scope:
        if snippet[0] == "FILE_START" or snippet[0] == "FILE_END":
            continue
        lc = snippet_license_info.get(snippet, None)
        cr = snippet_cr_info.get(snippet, None)
        if not lc and not cr:
            continue
            
        cnt += 1
        meta = component_meta_template(level)
        meta["component"]["componentType"] = "SNIPPET"
        meta["component"]["componentName"] = f"SNIPPET{cnt} in {path}"
        componentID = IDManager.get_componentID()
        meta["component"]["componentID"] = componentID
        meta["component"]["componentLocation"] = f"{fileID}<L>{snippet[3]}:{snippet[4]}"
        meta["component"]["componentLicense"] = lc
        meta["component"]["copyright"] = cr
        meta["component"]["componentChecksum"] = []
        algo_sha1.update(snippet[5])
        algo_md5.update(snippet[5])
        algo_sha256.update(snippet[5])
        meta["component"]["componentChecksum"].append({"Algorithm": "SHA1", "Checksum": algo_sha1.hexdigest()})
        meta["component"]["componentChecksum"].append({"Algorithm": "MD5", "Checksum": algo_md5.hexdigest()})
        meta["component"]["componentChecksum"].append({"Algorithm": "SHA256", "Checksum": algo_sha256.hexdigest()})

        if level == 3:
            meta["componentValid"]["componentID"] = componentID
            holder = snippet_holder_info.get(snippet, None)
            if holder:
                meta["componentValid"]["originator"] = holder
        
        component_list.append(meta)

    return component_list, license_list