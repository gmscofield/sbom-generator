# import sys
# sys.path.append("/home/jcg/SBOM/sbom-generator/SbomGT/")

import re
from typing import Union, List, Optional
from .middleware import Middleware, Component, Service, CrossRef, Text, Relationship, Hash, Annotation, License, Individual, Extension, ExternalReference, SnippetPointer, SnippetScope
from ..schema import spdx_model
from ..schema.cdx_model.spdx import Schema


class Spdx2Middleware:
    def __init__(self, spdx_bom: dict) -> None:
        self.spdx_bom = spdx_bom
        if spdx_bom["spdxVersion"] != "SPDX-2.3":
            raise ValueError("Only support SPDX 2.3 version")

    def spdx2middleware(self) -> Middleware:
        bom = spdx_model.Spdx23(**self.spdx_bom)
        midware = Middleware(
            doc_ID=bom.SPDXID,
            doc_name=bom.name,
            doc_namespace=bom.documentNamespace,
            timestamp=bom.creationInfo.created,
            licenses=[self.make_License_object(bom.dataLicense)]
        )
        
        bom_properties = []
        relationships = []
        midware_annotations = []
        if bom.annotations:
            for anno in bom.annotations:
                midware_annotations.append(
                    Annotation(
                        type=anno.annotationType.value if anno.annotationType else "OTHER",
                        subjects=[],
                        timestamp=anno.annotationDate,
                        annotator=[Spdx2Middleware.make_ind_or_comp_object(anno.annotator)] if anno.annotator else None,
                        text=anno.comment
                    )
                )
        if bom.revieweds:
            for review in bom.revieweds:
                midware_annotations.append(
                    Annotation(
                        type="REVIEW",
                        subjects=[],
                        timestamp=review.reviewDate,
                        annotator=[Spdx2Middleware.make_ind_or_comp_object(review.reviewer)] if review.reviewer else None,
                        text=review.comment
                    )
                )
        
        if bom.comment:
            bom_properties.append(
                Extension(
                    key="comment",
                    value=bom.comment
                )
            )
        
        if bom.creationInfo.comment:
            bom_properties.append(
                Extension(
                    key="creationInfo.comment",
                    value=bom.creationInfo.comment
                )
            )
        
        if bom.creationInfo.creators:
            creators = []
            for creator in bom.creationInfo.creators:
                creators.append(Spdx2Middleware.make_ind_or_comp_object(creator))
            midware.creator = creators
        
        midware.license_list_version = bom.creationInfo.licenseListVersion
        
        if bom.externalDocumentRefs:
            external_document_refs = []
            for ref in bom.externalDocumentRefs:
                external_document_refs.append(
                    ExternalReference(
                        url=f"{ref.externalDocumentId}({ref.spdxDocument})",
                        type="other",
                        checksum=self.checksum_spdx2mid([ref.checksum])
                    )
                )
            midware.external_references = external_document_refs
        
        if bom.documentDescribes:
            for desc in bom.documentDescribes:
                relationships.append(
                    Relationship(
                        type="DESCRIBES",
                        sourceID=bom.SPDXID,
                        targetID=desc,
                        comment="From deprecated SPDX 2.3 field 'documentDescribes'"
                    )
                )
        
        license_dict = {}
        if bom.hasExtractedLicensingInfos:
            for lic in bom.hasExtractedLicensingInfos:
                cross_refs = []
                if lic.crossRefs:
                    for ref in lic.crossRefs:
                        cross_refs.append(
                            CrossRef(
                                isLive=ref.isLive,
                                isValid=ref.isValid,
                                isWayBackLink=ref.isWayBackLink,
                                match=ref.match,
                                order=ref.order,
                                timestamp=ref.timestamp,
                                url=ref.url
                            )
                        )
                
                lic_properties = []
                if lic.comment:
                    lic_properties.append(
                        Extension(
                            key="comment",
                            value=lic.comment
                        )
                    )
                if lic.seeAlsos:
                    for i, see_also in enumerate(lic.seeAlsos):
                        lic_properties.append(
                            Extension(
                                key=f"seeAlso{i + 1}",
                                value=see_also
                            )
                        )
                
                license_dict[lic.licenseId] = License(
                    spdxID=lic.licenseId,
                    name=lic.name,
                    text=Text(content=lic.extractedText) if lic.extractedText else None,
                    crossRefs=cross_refs if cross_refs else None,
                    properties=lic_properties
                )
        
        components = []
        if bom.packages:
            for pkg in bom.packages:
                pkg_checksum = []
                if pkg.checksums:
                    for pkg_cs in pkg.checksums:
                        pkg_checksum.append(
                            Hash(
                                alg=pkg_cs.algorithm.value,
                                value=pkg_cs.checksumValue
                            )
                        )
                
                external_pkg_refs = []
                if pkg.externalRefs:
                    for ref in pkg.externalRefs:
                        external_pkg_refs.append(
                            ExternalReference(
                                url=ref.referenceLocator,
                                type=f"{ref.referenceCategory.value}({ref.referenceType})",
                                comment=ref.comment
                            )
                        )
                
                vcExcludedFiles = None
                vcValue = None
                if pkg.packageVerificationCode:
                    vcExcludedFiles = pkg.packageVerificationCode.packageVerificationCodeExcludedFiles
                    vcValue = pkg.packageVerificationCode.packageVerificationCodeValue
                
                licenses = []
                if pkg.licenseConcluded:
                    license_concluded = license_dict.get(pkg.licenseConcluded)
                    if not license_concluded:
                        license_concluded = self.make_License_object(pkg.licenseConcluded)
                    license_concluded.type = "concluded"
                    lic_properties = []
                    if pkg.licenseComments:
                        lic_properties.append(
                            Extension(
                                key="licenseComments",
                                value=pkg.licenseComments
                            )
                        )
                    if pkg.licenseInfoFromFiles:
                        for i, lic_info in enumerate(pkg.licenseInfoFromFiles):
                            lic_properties.append(
                                Extension(
                                    key=f"licenseInfoFromFiles{i + 1}",
                                    value=lic_info
                                )
                            )
                    license_concluded.properties = lic_properties if lic_properties else None
                    licenses.append(license_concluded)
                
                if pkg.licenseDeclared:
                    license_declared = license_dict.get(pkg.licenseDeclared)
                    if not license_declared:
                        license_declared = self.make_License_object(pkg.licenseDeclared)
                    license_declared.type = "declared"
                    licenses.append(license_declared)
                
                pkg_properties = []
                if pkg.comment:
                    pkg_properties.append(
                        Extension(
                            key="comment",
                            value=pkg.comment
                        )
                    )
                if pkg.filesAnalyzed != None:
                    pkg_properties.append(
                        Extension(
                            key="filesAnalyzed",
                            value=str(pkg.filesAnalyzed)
                        )
                    )
                if pkg.summary:
                    pkg_properties.append(
                        Extension(
                            key="summary",
                            value=pkg.summary
                        )
                    )
                
                comp_type = "Package"
                if pkg.primaryPackagePurpose:
                    comp_type += (": " + pkg.primaryPackagePurpose.value)
                
                components.append(
                    Component(
                        type=comp_type,
                        name=f"{pkg.name}({pkg.packageFileName})" if pkg.packageFileName else f"{pkg.name}",
                        version=pkg.versionInfo,
                        ID=pkg.SPDXID,
                        originator=[Spdx2Middleware.make_ind_or_comp_object(pkg.originator)] if pkg.originator else None,
                        supplier=Spdx2Middleware.make_ind_or_comp_object(pkg.supplier),
                        licenses=licenses if licenses else None,
                        copyright=pkg.copyrightText if pkg.copyrightText else None,
                        checksum=self.checksum_spdx2mid(pkg.checksums),
                        external_references=external_pkg_refs if external_pkg_refs else None,
                        verificationCodeExcludedFiles=vcExcludedFiles,
                        verificationCodeValue=vcValue,
                        download_location=pkg.downloadLocation,
                        homepage=pkg.homepage,
                        source_info=pkg.sourceInfo,
                        description=pkg.description,
                        built_date=pkg.builtDate,
                        release_date=pkg.releaseDate,
                        valid_until_date=pkg.validUntilDate,
                        tags=pkg.attributionTexts,
                        properties=pkg_properties if pkg_properties else None
                    )
                )
                
                if pkg.hasFiles:
                    for file_id in pkg.hasFiles:
                        relationships.append(
                            Relationship(
                                type="CONTAINS",
                                sourceID=pkg.SPDXID,
                                targetID=file_id,
                                comment="From deprecated SPDX 2.3 field 'hasFiles'"
                            )
                        )
                
                if pkg.annotations:
                    for anno in pkg.annotations:
                        midware_annotations.append(
                            Annotation(
                                type=anno.annotationType.value if anno.annotationType else "OTHER",
                                subjects=[pkg.SPDXID],
                                timestamp=anno.annotationDate,
                                annotator=[Spdx2Middleware.make_ind_or_comp_object(anno.annotator)] if anno.annotator else None,
                                text=anno.comment
                            )
                        )
        
        if bom.files:
            for file in bom.files:
                file_properties = []
                if file.comment:
                    file_properties.append(
                        Extension(
                            key="comment",
                            value=file.comment
                        )
                    )
                
                if file.noticeText:
                    file_properties.append(
                        Extension(
                            key="noticeText",
                            value=file.noticeText
                        )
                    )
                    
                if file.fileContributors:
                    for i, contrib in enumerate(file.fileContributors):
                        file_properties.append(
                            Extension(
                                key=f"fileContributors{i + 1}",
                                value=contrib
                            )
                        )
                
                if file.artifactOfs:
                    for item in file.artifactOfs:
                        key, value = list(item.items())[0]
                        if isinstance(value, str):
                            file_properties.append(
                                Extension(
                                    key=f"artifactOfs-{key}",
                                    value=value
                                )
                            )
                
                if file.fileDependencies:
                    for relation in file.fileDependencies:
                        relationships.append(
                            Relationship(
                                type="DEPENDS_ON",
                                sourceID=file.SPDXID,
                                targetID=relation,
                                comment="From deprecated SPDX 2.0 field 'fileDependencies'"
                            )
                        )
                
                licenses = []
                if file.licenseConcluded:
                    license_concluded = license_dict.get(file.licenseConcluded)
                    if not license_concluded:
                        license_concluded = self.make_License_object(file.licenseConcluded)
                    license_concluded.type = "concluded"
                    lic_properties = []
                    if file.licenseComments:
                        lic_properties.append(
                            Extension(
                                key="licenseComments",
                                value=file.licenseComments
                            )
                        )
                    if file.licenseInfoInFiles:
                        for i, lic_info in enumerate(file.licenseInfoInFiles):
                            lic_properties.append(
                                Extension(
                                    key=f"licenseInfoInFiles{i + 1}",
                                    value=lic_info
                                )
                            )
                    license_concluded.properties = lic_properties if lic_properties else None
                    licenses.append(license_concluded)
                
                filetype = "File"
                mime_type = None
                if file.fileTypes:
                    filetype += ": "
                    type_str = []
                    for one_type in file.fileTypes:
                        type_str.append(one_type.value)
                    filetype += ", ".join(type_str)
                if filetype in ['IMAGE', 'VIDEO', 'APPLICATION', 'BINARY', 'AUDIO'] and len(file.fileName.split(".")) > 1:
                    suffix = file.fileName.split(".")[-1]
                    mime_type = f"{filetype.lower()}/{suffix}"
                    
                components.append(
                    Component(
                        type=filetype,
                        mime_type=mime_type,
                        ID=file.SPDXID,
                        tags=file.attributionTexts,
                        checksum=self.checksum_spdx2mid(file.checksums),
                        licenses=licenses if licenses else None,
                        copyright=file.copyrightText,
                        name=file.fileName,
                        properties=file_properties if file_properties else None,
                    )
                )
                
                if file.annotations:
                    for anno in file.annotations:
                        midware_annotations.append(
                            Annotation(
                                type=anno.annotationType.value if anno.annotationType else "OTHER",
                                subjects=[file.SPDXID],
                                timestamp=anno.annotationDate,
                                annotator=Spdx2Middleware.make_ind_or_comp_object(anno.annotator) if anno.annotator else None,
                                text=anno.comment
                            )
                        )
        
        if bom.snippets:
            for snippet in bom.snippets:
                snippet_properties = []
                if snippet.comment:
                    snippet_properties.append(
                        Extension(
                            key="comment",
                            value=snippet.comment
                        )
                    )
                
                licenses = []
                if snippet.licenseConcluded:
                    license_concluded = license_dict.get(snippet.licenseConcluded)
                    if not license_concluded:
                        license_concluded = self.make_License_object(snippet.licenseConcluded)
                    license_concluded.type = "concluded"
                    lic_properties = []
                    if snippet.licenseComments:
                        lic_properties.append(
                            Extension(
                                key="licenseComments",
                                value=snippet.licenseComments
                            )
                        )
                    if snippet.licenseInfoInSnippets:
                        for i, lic_info in enumerate(snippet.licenseInfoInSnippets):
                            lic_properties.append(
                                Extension(
                                    key=f"licenseInfoInSnippets{i + 1}",
                                    value=lic_info
                                )
                            )
                    license_concluded.properties = lic_properties if lic_properties else None
                    licenses = [license_concluded]
                
                scope = []
                for range in snippet.ranges:
                    endPt = SnippetPointer(
                        offset=range.endPointer.offset,
                        lineNumber=range.endPointer.lineNumber
                    )
                    startPt = SnippetPointer(
                        offset=range.startPointer.offset,
                        lineNumber=range.startPointer.lineNumber
                    )
                    scope.append(
                        SnippetScope(
                            endPointer=endPt,
                            startPointer=startPt,
                            fromFile=snippet.snippetFromFile
                        )
                    )
                
                components.append(
                    Component(
                        type="Snippet",
                        ID=snippet.SPDXID,
                        tags=snippet.attributionTexts,
                        properties=snippet_properties if snippet_properties else None,
                        copyright=snippet.copyrightText,
                        name=snippet.name,
                        licenses=licenses if licenses else None,
                        scope=scope if scope else None
                    )
                )
                
                if snippet.annotations:
                    for anno in snippet.annotations:
                        midware_annotations.append(
                            Annotation(
                                type=anno.annotationType.value if anno.annotationType else "OTHER",
                                subjects=[snippet.SPDXID],
                                timestamp=anno.annotationDate,
                                annotator=Spdx2Middleware.make_ind_or_comp_object(anno.annotator) if anno.annotator else None,
                                text=anno.comment
                            )
                        )
        
        if bom.relationships:
            for relation in bom.relationships:
                relationships.append(
                    Relationship(
                        type=relation.relationshipType.value,
                        sourceID=relation.spdxElementId,
                        targetID=relation.relatedSpdxElement,
                        comment=relation.comment
                    )
                )
        
        midware.components = components if components else None
        midware.relationship = relationships if relationships else None
        midware.annotations = midware_annotations if midware_annotations else None
        midware.properties = bom_properties if bom_properties else None
        return midware

    @staticmethod
    def make_ind_or_comp_object(spdx_str: Optional[str]) -> Optional[Union[Individual, Component]]:
        if spdx_str == None:
            return None
        if spdx_str == "NOASSERTION":
            return Individual(
                type="person",
                name="NOASSERTION"
            )
        pattern = r'^(Person|Organization):\s+([^\(]+?)(\s*\([^\)]+\))?$|^Tool:\s+([^\s]+)(\s*-\s*.+)?$'
        match = re.match(pattern, spdx_str)
        if not match:
            if spdx_str.startswith("Person:"):
                return Individual(
                    type="person",
                    name=spdx_str.split(":")[1].strip()
                )
            elif spdx_str.startswith("Organization:"):
                return Individual(
                    type="organization",
                    name=spdx_str.split(":")[1].strip()
                )
            elif spdx_str.startswith("Tool:"):
                return Component(
                    name=spdx_str.split(":")[1].strip()
                )
        group = match.groups()
        if group[0] == "Person":
            return Individual(
                type="person",
                name=group[1],
                email=group[2].strip().strip("(").strip(")") if group[2] else None
            )
        elif group[0] == "Organization":
            return Individual(
                type="organization",
                name=group[1],
                email=group[2].strip().strip("(").strip(")") if group[2] else None
            )
        else:
            return Component(
                name=group[3],
                version=group[4]
            )

    def make_License_object(self, license_string: str) -> License:
        if license_string in [member.value for member in Schema]:
            return License(spdxID=license_string)
        else:
            return License(name=license_string)
    
    def checksum_spdx2mid(self, checksums: Optional[List[spdx_model.Checksum]]) -> Optional[List[Hash]]:
        if not checksums:
            return None
        checksum_list = []
        for checksum in checksums:
            checksum_list.append(
                Hash(
                    alg=checksum.algorithm.value,
                    value=checksum.checksumValue
                )
            )
        return checksum_list


class Middleware2Spdx:
    def __init__(self, midware: Middleware) -> None:
        self.midware = midware

    def middleware2spdx(self) -> dict:
        data_license = []
        for lic in self.midware.licenses:
            if lic.spdxID:
                data_license.append(lic.spdxID)
            else:
                data_license.append(lic.name)
        
        createinfo_comment = Middleware2Spdx.match_property("creationInfo.comment", self.midware.properties)
        creation_info = spdx_model.CreationInfo(
            created=self.midware.timestamp,
            creators=Middleware2Spdx.individual2str(self.midware.creator),
            licenseListVersion=self.midware.license_list_version,
            comment=" ".join(createinfo_comment) if createinfo_comment else None
        )
        
        bom_comment = Middleware2Spdx.match_property("comment", self.midware.properties)
        bom = spdx_model.Spdx23(
            spdxVersion="SPDX-2.3",
            SPDXID=self.midware.doc_ID,
            dataLicense=" AND ".join(data_license),
            name=self.midware.doc_name,
            documentNamespace=self.midware.doc_namespace,
            creationInfo=creation_info,
            comment=" ".join(bom_comment) if bom_comment else None
        )
        
        bom_annotations = []
        if self.midware.annotations:
            for anno in self.midware.annotations:
                if len(anno.subjects) == 0:
                    bom_annotations.append(
                        spdx_model.Annotation(
                            annotationType=anno.type.upper() if anno.type.upper() in [member.value for member in spdx_model.AnnotationType] else spdx_model.AnnotationType.OTHER,
                            annotationDate=anno.timestamp,
                            annotator=Middleware2Spdx.individual2str([anno.annotator])[0],
                            comment=anno.text
                        )
                    )
        
        if self.midware.lifecycles:
            bom_annotations.append(
                spdx_model.Annotation(
                    annotationType=spdx_model.AnnotationType.OTHER,
                    annotationDate=bom.creationInfo.created,
                    annotator=", ".join(bom.creationInfo.creators),
                    comment="Lifecycles: " + ", ".join(self.midware.lifecycles)
                )
            )
        
        if self.midware.properties:
            for prop in self.midware.properties:
                bom_annotations.append(
                    spdx_model.Annotation(
                        annotationType=spdx_model.AnnotationType.OTHER,
                        annotationDate=bom.creationInfo.created,
                        annotator=", ".join(bom.creationInfo.creators),
                        comment=f"{prop.key}: {prop.value}"
                    )
                )
        
        if self.midware.external_references:
            external_refs = []
            for ref in self.midware.external_references:
                external_refs.append(
                    spdx_model.ExternalDocumentRef(
                        checksum=self.checksum_mid2spdx(ref.checksum)[0] if ref.checksum else None,
                        externalDocumentId=ref.url.split("(")[0],
                        spdxDocument=ref.url.split("(")[1].strip().strip(")") if len(ref.url.split("(")) > 1 else None
                    )
                )
            bom.externalDocumentRefs = external_refs
        
        packages = []
        files = []
        snippets = []
        licenses = []
        if self.midware.components:
            for comp in self.midware.components:
                annotations = []
                if comp.mime_type:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"MIME Type: {comp.mime_type}"
                        )
                    )
                
                if comp.scope and isinstance(comp.scope, str):
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"scope: {comp.scope}"
                        )
                    )
                
                if comp.publisher:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"publisher: {Middleware2Spdx.individual2str([comp.publisher])[0]}"
                        )
                    )
                
                if comp.group:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"group: {comp.group}"
                        )
                    )
                
                if comp.purl:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"purl: {comp.purl}"
                        )
                    )
                
                if comp.cpe:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"cpe: {comp.cpe}"
                        )
                    )
                
                if comp.omniborId:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"omniborId: {', '.join(comp.omniborId)}"
                        )
                    )
                
                if comp.swhid:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"swhid: {', '.join(comp.swhid)}"
                        )
                    )
                
                if comp.swid:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"swid: {comp.swid.model_dump_json(exclude_none=True)}"
                        )
                    )
                
                if comp.source_repo:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"source_repo: {comp.source_repo}"
                        )
                    )
                
                if comp.releaseNotes:
                    annotations.append(
                        spdx_model.Annotation(
                            annotationType=spdx_model.AnnotationType.OTHER,
                            annotationDate=bom.creationInfo.created,
                            annotator=", ".join(bom.creationInfo.creators),
                            comment=f"releaseNotes: {comp.releaseNotes.model_dump_json(exclude_none=True)}"
                        )
                    )
                
                license_comment = ""
                license_concluded = ""
                license_declared = ""
                license_info = []
                if comp.licenses:
                    for lic in comp.licenses:
                        if ((lic.spdxID != "NOASSERTION" and lic.name != "NOASSERTION") or (lic.spdxID != "NONE" and lic.name != "NONE")) and (lic.text):
                            cross_refs = []
                            if lic.crossRefs:
                                for ref in lic.crossRefs:
                                    cross_refs.append(
                                        spdx_model.CrossRef(
                                            isLive=ref.isLive,
                                            isValid=ref.isValid,
                                            isWayBackLink=ref.isWayBackLink,
                                            match=ref.match,
                                            order=ref.order,
                                            timestamp=ref.timestamp,
                                            url=ref.url
                                        )
                                    )
                            lic_comment = Middleware2Spdx.match_property("comment", lic.properties)
                            licenses.append(
                                spdx_model.HasExtractedLicensingInfo(
                                    comment=" ".join(lic_comment) if lic_comment else None,
                                    seeAlsos=Middleware2Spdx.match_property("seeAlso", lic.properties),
                                    crossRefs=cross_refs if cross_refs else None,
                                    extractedText=lic.text.content if lic.text else None,
                                    name=lic.name,
                                    licenseId=lic.spdxID,
                                )
                            )
                        
                        if lic.type == "concluded":
                            if license_concluded:
                                license_concluded += " AND "
                            lic_str = lic.spdxID if lic.spdxID else lic.name
                            if lic_str:
                                license_concluded += lic_str
                            if lic.properties:
                                for prop in lic.properties:
                                    if prop.key == "licenseComments":
                                        license_comment = prop.value
                                    else:
                                        license_info.append(prop.value)
                        else:
                            if license_declared:
                                license_declared += " AND "
                            lic_str = lic.spdxID if lic.spdxID else lic.name
                            if lic_str:
                                license_declared += lic_str
                            if lic.properties:
                                for prop in lic.properties:
                                    if prop.key == "licenseComments":
                                        license_comment = prop.value
                                    else:
                                        license_info.append(prop.value)
                
                comments = Middleware2Spdx.match_property("comment", comp.properties)
                comment = " ".join(comments) if comments else None
                
                if self.judge_comp_type(comp) == "Package":
                    external_pkg_refs = []
                    if comp.external_references:
                        for ref in comp.external_references:
                            ref_cat = ref.type.split("(")[0]
                            if not ref_cat in [member.value for member in spdx_model.ReferenceCategory]:
                                ref_cat = "OTHER"
                            ref_type = ref.type.split("(")[1].strip().strip(")") if len(ref.type.split("(")) > 1 else None
                            if not ref_type:
                                ref_type = "OTHER"
                            external_pkg_refs.append(
                                spdx_model.ExternalRef(
                                    referenceCategory=spdx_model.ReferenceCategory(ref_cat),
                                    referenceLocator=ref.url,
                                    referenceType=ref_type,
                                    comment=ref.comment
                                )
                            )
                    
                    files_analyzed = Middleware2Spdx.match_property("filesAnalyzed", comp.properties)
                    if not files_analyzed:
                        files_analyzed = None
                    elif files_analyzed[0] == "True":
                        files_analyzed = True
                    else:
                        files_analyzed = False
                    
                    pkgVerificationCode = None
                    if comp.verificationCodeExcludedFiles or comp.verificationCodeValue:
                        pkgVerificationCode = spdx_model.PackageVerificationCode(
                            packageVerificationCodeExcludedFiles=comp.verificationCodeExcludedFiles,
                            packageVerificationCodeValue=comp.verificationCodeValue
                        )
                    
                    primaryPkgPurpose = None
                    type_str = comp.type.split(":")
                    if len(type_str) > 1 and type_str[1].strip() in [member.value for member in spdx_model.PrimaryPackagePurpose]:
                        primaryPkgPurpose = spdx_model.PrimaryPackagePurpose(comp.type.split(":")[1].strip())
                    
                    pkgFileName = None
                    if comp.name.find("(") != -1:
                        pkgFileName = comp.name.split("(")[1].strip().strip(")")
                    
                    summary_property = Middleware2Spdx.match_property("summary", comp.properties)
                    summary = None
                    if summary_property:
                        summary = " ".join(summary_property)
                    
                    originator = None
                    if comp.originator:
                        originator_str = Middleware2Spdx.individual2str(comp.originator)
                        originator = " ".join(originator_str)
                    
                    supplier = None
                    if comp.supplier:
                        supplier_str = Middleware2Spdx.individual2str([comp.supplier])
                        supplier = " ".join(supplier_str)
                    
                    download_loc = comp.download_location
                    if not download_loc:
                        download_loc = "NOASSERTION"
                    pkg = spdx_model.Package(
                        SPDXID=comp.ID,
                        attributionTexts=comp.tags,
                        builtDate=comp.built_date,
                        checksums=self.checksum_mid2spdx(comp.checksum),
                        comment=comment,
                        copyrightText=comp.copyright,
                        description=comp.description,
                        downloadLocation=download_loc,
                        externalRefs=external_pkg_refs,
                        filesAnalyzed=files_analyzed,
                        homepage=comp.homepage,
                        licenseComments=license_comment if license_comment else None,
                        licenseConcluded=license_concluded if license_concluded else None,
                        licenseDeclared=license_declared if license_declared else None,
                        licenseInfoFromFiles=license_info if license_info else None,
                        name=comp.name,
                        originator=originator,
                        packageFileName=pkgFileName,
                        packageVerificationCode=pkgVerificationCode,
                        primaryPackagePurpose=primaryPkgPurpose,
                        releaseDate=comp.release_date,
                        sourceInfo=comp.source_info,
                        summary=summary,
                        supplier=supplier,
                        validUntilDate=comp.valid_until_date,
                        versionInfo=comp.version,
                    )
                    if comp.properties:
                        for prop in comp.properties:
                            annotations.append(
                                spdx_model.Annotation(
                                    annotationType=spdx_model.AnnotationType.OTHER,
                                    annotationDate=bom.creationInfo.created,
                                    annotator=", ".join(bom.creationInfo.creators),
                                    comment=f"{prop.key}: {prop.value}"
                                )
                            )
                    pkg.annotations = annotations if annotations else None
                    packages.append(pkg)
                    
                elif self.judge_comp_type(comp) == "File":
                    notice_text = Middleware2Spdx.match_property("noticeText", comp.properties)
                    notice_text = " ".join(notice_text) if notice_text else None
                    
                    file_types = []
                    if comp.type:
                        type_str = comp.type.strip("File: ")
                        for one_type in type_str.split(", "):
                            if one_type in [member.value for member in spdx_model.FileType]:
                                file_types.append(spdx_model.FileType(one_type))
                            else:
                                file_types.append(spdx_model.FileType.OTHER)
                    
                    file = spdx_model.File(
                        SPDXID=comp.ID,
                        artifactOfs=Middleware2Spdx.match_property("artifactOfs", comp.properties),
                        attributionTexts=comp.tags,
                        checksums=self.checksum_mid2spdx(comp.checksum),
                        comment=comment,
                        copyrightText=comp.copyright,
                        fileContributors=Middleware2Spdx.match_property("fileContributors", comp.properties),
                        fileName=comp.name,
                        fileTypes=file_types if file_types else None,
                        licenseComments=license_comment if license_comment else None,
                        licenseConcluded=license_concluded if license_concluded else None,
                        licenseInfoInFiles=license_info if license_info else None,
                        noticeText=notice_text,
                    )
                    if comp.properties:
                        for prop in comp.properties:
                            annotations.append(
                                spdx_model.Annotation(
                                    annotationType=spdx_model.AnnotationType.OTHER,
                                    annotationDate=bom.creationInfo.created,
                                    annotator=", ".join(bom.creationInfo.creators),
                                    comment=f"{prop.key}: {prop.value}"
                                )
                            )
                    file.annotations = annotations if annotations else None
                    files.append(file)
                
                else:
                    ranges = []
                    from_file = None
                    for range in comp.scope:
                        spdx_range = spdx_model.Range(
                            endPointer=spdx_model.EndPointer(
                                reference=range.fromFile,
                                offset=range.endPointer.offset,
                                lineNumber=range.endPointer.lineNumber
                            ),
                            startPointer=spdx_model.StartPointer(
                                reference=range.fromFile,
                                offset=range.startPointer.offset,
                                lineNumber=range.startPointer.lineNumber
                            )
                        )
                        ranges.append(spdx_range)
                        from_file = range.fromFile
                    
                    snippet = spdx_model.Snippet(
                        SPDXID=comp.ID,
                        attributionTexts=comp.tags,
                        comment=comment,
                        copyrightText=comp.copyright,
                        licenseComments=license_comment,
                        licenseConcluded=license_concluded,
                        licenseInfoInSnippets=license_info,
                        name=comp.name,
                        ranges=ranges,
                        snippetFromFile=from_file
                    )
                    if comp.properties:
                        for prop in comp.properties:
                            annotations.append(
                                spdx_model.Annotation(
                                    annotationType=spdx_model.AnnotationType.OTHER,
                                    annotationDate=bom.creationInfo.created,
                                    annotator=", ".join(bom.creationInfo.creators),
                                    comment=f"{prop.key}: {prop.value}"
                                )
                            )
                    snippet.annotations = annotations if annotations else None
                    snippets.append(snippet)
        
        relationships = []
        if self.midware.relationship:
            for relation in self.midware.relationship:
                spdx_relation_type = None
                relation_type = relation.type.upper().replace("-", "_")
                if relation_type in [member.value for member in spdx_model.RelationshipType]: 
                    spdx_relation_type = spdx_model.RelationshipType(relation_type)
                else:
                    spdx_relation_type = spdx_model.RelationshipType.OTHER
                
                relationships.append(
                    spdx_model.Relationship(
                        spdxElementId=relation.sourceID,
                        relatedSpdxElement=relation.targetID,
                        comment=relation.comment,
                        relationshipType=spdx_relation_type
                    )
                )
        
        bom.packages = packages if packages else None
        bom.files = files if files else None
        bom.snippets = snippets if snippets else None
        bom.relationships = relationships if relationships else None
        bom.hasExtractedLicensingInfos = licenses if licenses else None
        return bom.model_dump(mode='json', by_alias=True, exclude_none=True)

    @staticmethod
    def match_property(key: str, extensions: Optional[List[Extension]]) -> Optional[List[str]]:
        matched_exts = []
        if not extensions:
            return None
        for ext in extensions:
            if ext.key.lower().startswith(key.lower()):
                matched_exts.append(ext.value)
                extensions.remove(ext)
        if not matched_exts:
            return None
        return matched_exts

    @staticmethod
    def individual2str(creator_object: Optional[List[Union[Individual, Component, Service]]]) -> List[str]:
        if not creator_object:
            return None
        creators = []
        for creator in creator_object:
            if not creator:
                continue
            if isinstance(creator, Individual):
                if creator.type == "person":
                    ind = f"Person: {creator.name}"
                else:
                    ind = f"Organization: {creator.name}"
                if creator.email:
                    ind += f" ({creator.email})"
                creators.append(ind)
            else:
                tool = f"Tool: {creator.name}"
                if creator.version:
                    tool += f" - {creator.version}"
                creators.append(tool)
        if not creators:
            return None
        return creators

    def checksum_mid2spdx(self, checksum: Optional[List[Hash]]) -> Optional[List[spdx_model.Checksum]]:
        if not checksum:
            return None
        checksums = []
        for cs in checksum:
            if cs.alg in [member.value for member in spdx_model.Algorithm]:
                checksums.append(
                    spdx_model.Checksum(
                        algorithm=spdx_model.Algorithm(cs.alg.upper().replace("_", "-")),
                        checksumValue=cs.value
                    )
                )
        return checksums
    
    def judge_comp_type(self, comp: Component) -> str:
        if not comp.type:
            return "Package"
        if comp.type.startswith("Package"):
            return "Package"
        elif comp.type.startswith("File"):
            return "File"
        elif comp.type.startswith("Snippet"):
            return "Snippet"
        else:
            for pkg_type in [member.value for member in spdx_model.PrimaryPackagePurpose]:
                if pkg_type.lower() in comp.type.lower():
                    return "Package"
            for file_type in [member.value for member in spdx_model.FileType]:
                if file_type.lower() in comp.type.lower():
                    return "File"
            return "Package"


if __name__ == '__main__':
    import json
    # path = "/home/jcg/SBOM/sbom-example/scancode-sbom/syft-spdx.json"
    # bom = json.load(open(path, "r"))
    # midware = spdx2middleware(bom)
    # midware_json = midware.model_dump(by_alias=True, exclude_none=True)
    # json.dump(midware_json, open("/home/jcg/SBOM/sbom-generator/SbomGT/output/midware.json", "w"), indent=4)
    
    
    
    examples = [
        "/home/jcg/SBOM/sbom-generator/SbomGT/example/test.spdx.json",
        "/home/jcg/SBOM/sbom-generator/SbomGT/example/test1.spdx.json",
        "/home/jcg/SBOM/sbom-generator/SbomGT/example/test2.spdx.json",
        "/home/jcg/SBOM/sbom-generator/SbomGT/example/test3.spdx.json",
        "/home/jcg/SBOM/sbom-example/scancode-sbom/syft-spdx.json",
        "/home/jcg/SBOM/sbom-example/scancode-sbom/cdx-bin-tool-spdx.json"
    ]
    for path in examples:
        print(path)
        bom = json.load(open(path, "r"))
        midware = Spdx2Middleware(bom).spdx2middleware()
        midware_json = midware.model_dump(by_alias=True, exclude_none=True)
        json.dump(midware_json, open("/home/jcg/SBOM/sbom-generator/SbomGT/output/midware.json", "w"), indent=4)
        midware = json.load(open("/home/jcg/SBOM/sbom-generator/SbomGT/output/midware.json", "r"))
        Middleware2Spdx(Middleware(**midware)).middleware2spdx()