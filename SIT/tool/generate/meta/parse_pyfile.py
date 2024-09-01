import ast
from  typing import List, Optional
import hashlib
from scancode_toolkit.src.scancode.api import get_licenses, get_copyrights, get_file_info
from  .utils import name_email_str2ind, IDManager
from ....output import middleware


def copyright_from_pkgfile(path: str) -> Optional[str]:
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


def get_snippet_scope(path: str):
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


def get_single_snippet_loc(snippet_scope: list, lineno: int) -> Optional[tuple]:
    min_line = 0
    min_snippet = None
    for snippet in snippet_scope:
        if snippet[1] <= lineno and snippet[2] >= lineno and min_line <= snippet[1]:
            min_line = snippet[1]
            min_snippet = snippet
    return min_snippet


def analyze_pyfile_meta(path: str) -> Optional[List]:
    snippet_scope = get_snippet_scope(path)
    if not snippet_scope:
        return None

    component_list = []
    license_info = get_licenses(path, include_text = True, unknown_licenses=True)
    file_spdx_id = license_info.get("detected_license_expression_spdx", None)
    if not file_spdx_id:
        return None
    file_info = get_file_info(path)
    cr_info = get_copyrights(path)
    all_cr = cr_info.get("copyrights", [])
    
    file_lic = middleware.License(
        type="concluded",
        spdxID=file_spdx_id,
        name=license_info.get("detected_license_expression", None),
    )
    checksums = []
    if file_info.get("sha1", None):
        checksums.append(
            middleware.Hash(
                alg="SHA1",
                value=file_info["sha1"]
            )
        )
    if file_info.get("md5", None):
        checksums.append(
            middleware.Hash(
                alg="MD5",
                value=file_info["md5"]
            )
        )
    if file_info.get("sha256", None):
        checksums.append(
            middleware.Hash(
                alg="SHA256",
                value=file_info["sha256"]
            )
        )
    fileID = IDManager.get_innerID()
    comp = middleware.Component(
        type="File: SOURCE",
        mime_type=file_info.get("mime_type", None),
        name=path,
        ID=fileID,
        licenses=[file_lic],
        checksum=checksums,
    )
    
    all_holder = cr_info.get("holders", [])
    file_copyright = ""
    snippet_cr_info = {}
    snippet_holder_info = {}
    for cr in all_cr:
        snippet = get_single_snippet_loc(snippet_scope, cr["start_line"])
        if not snippet:
            continue
        if snippet[0] == "FILE_START" or snippet[0] == "FILE_END":
            file_copyright += cr["copyright"]
        else:
            if not snippet in snippet_cr_info:
                snippet_cr_info[snippet] = cr["copyright"]
            else:
                snippet_cr_info[snippet] += cr["copyright"]
        
        for holder in all_holder:
            if holder["start_line"] == cr["start_line"]:
                snippet_holder_info[snippet] = holder["holder"]

    comp.copyright = file_copyright
    component_list.append(comp)

    detect_licenses = license_info.get("license_detections", [])
    snippet_license_info = {}
    for lc in detect_licenses:
        if not lc["license_expression_spdx"]:
            continue
        snippet = get_single_snippet_loc(snippet_scope, lc["matches"][0]["start_line"])
        if not snippet:
            continue
        if not snippet[0] == "FILE_START" and not snippet[0] == "FILE_END":
            snippet_lic = snippet_license_info.get(snippet, [])
            snippet_lic.append(
                middleware.License(
                    type="concluded",
                    spdxID=lc["license_expression_spdx"],
                    name=lc["license_expression"]
                )
            )
            snippet_license_info[snippet] = snippet_lic

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
        
        checksums = []
        if snippet[5] != -1:
            algo_sha1.update(snippet[5])
            algo_md5.update(snippet[5])
            algo_sha256.update(snippet[5])
            checksums.append(
                middleware.Hash(
                    alg="SHA1",
                    value=algo_sha1.hexdigest()
                )
            )
            checksums.append(
                middleware.Hash(
                    alg="MD5",
                    value=algo_md5.hexdigest()
                )
            )
            checksums.append(
                middleware.Hash(
                    alg="SHA256",
                    value=algo_sha256.hexdigest()
                )
            )
        
        comp = middleware.Component(
            type="Snippet",
            name=f"SNIPPET{cnt} in {path}",
            ID=IDManager.get_innerID(),
            scope=[middleware.SnippetScope(
                endPointer=middleware.SnippetPointer(
                    offset=snippet[4],
                    lineNumber=snippet[2]
                ),
                startPointer=middleware.SnippetPointer(
                    offset=snippet[3],
                    lineNumber=snippet[1]
                ),
                fromFile=fileID
            )],
            licenses=lc,
            copyright=cr,
            checksum=checksums if checksums else None
        )
        holder = snippet_holder_info.get(snippet, None)
        if holder:
            orig = name_email_str2ind(holder, None)
            comp.originator = [orig] if orig else None
        
        component_list.append(comp)

    return component_list
