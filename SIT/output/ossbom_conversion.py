# import sys
# sys.path.append("/home/jcg/SBOM/sbom-generator/SIT/")

from .middleware import Middleware, Component, SnippetScope, SnippetPointer, Service, CrossRef, Relationship, Hash, Annotation, License, Individual, Extension, ExternalReference, Text
from ..schema import ossbom_model
from ..schema.cdx_model.spdx import Schema
from typing import Optional, List, Union
from .spdx_conversion import Spdx2Middleware, Middleware2Spdx


class Ossbom2Middleware:
    def __init__(self, ossbom: dict) -> None:
        if ossbom.get("DocumentInformation", {}).get("DocumentVersion", None) != "1.0":
            raise Exception("Only support OSSBOM version 1.0")
        self.ossbom = ossbom
    
    def ossbom2middleware(self) -> Middleware:
        bom = ossbom_model.OSSBOM(**self.ossbom)
        
        license_info = {}
        if bom.OtherLicensingInformation:
            for lic in bom.OtherLicensingInformation:
                license_info[lic.LicenseID] = lic
        
        midware_lic = self.make_midware_license(bom.DocumentInformation.DocumentLicense, license_info)
        if midware_lic:
            midware_lic = [midware_lic]
        midware = Middleware(
            doc_ID=bom.DocumentInformation.DocumentID,
            doc_name=bom.DocumentInformation.DocumentName,
            doc_namespace="https://ossbom.org/schema/bom/1.0",
            timestamp=bom.ValidityInformation.DocumentCreationTime,
            licenses=midware_lic,
            license_list_version=bom.ValidityInformation.LicenseListVersion,
            creator=[Spdx2Middleware.make_ind_or_comp_object(bom.ValidityInformation.DocumentCreator)],
        )
        midware.external_references = self.exRefs_ossbom2midware(bom.DocumentInformation.DocumentRef)

        valid_info = {}
        if bom.ValidityInformation.ResourceValidityInfo:
            for info in bom.ValidityInformation.ResourceValidityInfo:
                valid_info[info.ResourceID] = info
        
        components = []
        if bom.PackageInformation:
            for pkg in bom.PackageInformation:
                lic = self.make_midware_license(pkg.DeclaredLicense, license_info)
                if lic:
                    lic = [lic]
                comp = Component(
                    type="Package: LIBRARY",
                    name=pkg.PackageName,
                    version=pkg.PackageVersion,
                    ID=pkg.PackageID,
                    checksum=self.hashes_ossbom2midware(pkg.PackageChecksum),
                    licenses=lic,
                    copyright=pkg.Copyright,
                    properties=self.properties_ossbom2midware(pkg.Properties),
                    external_references=self.exRefs_ossbom2midware(pkg.PackageRef)
                )
                pkg_valid = valid_info.get(pkg.PackageID, None)
                if pkg_valid:
                    comp.supplier = Spdx2Middleware.make_ind_or_comp_object(pkg_valid.Supplier)
                    comp.originator = [Spdx2Middleware.make_ind_or_comp_object(pkg_valid.Originator)]
                    comp.download_location = pkg_valid.DownloadLocation
                    comp.source_repo = pkg_valid.SourceRepository
                    comp.homepage = pkg_valid.HomePage
                    comp.release_date = pkg_valid.ReleaseTime
                    comp.built_date = pkg_valid.BuiltTime
                    comp.valid_until_date = pkg_valid.ValidUntilTime
                    
                components.append(comp)
        
        if bom.InnerInformation:
            for inner in bom.InnerInformation:
                if inner.InnerType == "FILE":
                    inner_type = "File"
                elif inner.InnerType == "SNIPPET":
                    inner_type = "Snippet"
                
                snippet_loc = None
                if inner.InnerLocation:
                    loc = inner.InnerLocation.split("<L>")
                    start_offset, end_offset = loc[1].split(":")
                    if inner_type == "Snippet":
                        end_pt = SnippetPointer(
                            offset=end_offset,
                        )
                        start_pt = SnippetPointer(
                            offset=start_offset,
                        )
                        snippet_loc = [
                            SnippetScope(
                                endPointer=end_pt,
                                startPointer=start_pt,
                                fromFile=loc[0],
                            )
                        ]
                
                lic = self.make_midware_license(inner.DeclaredLicense, license_info)
                if lic:
                    lic = [lic]
                
                comp = Component(
                    type=inner_type,
                    name=inner.InnerName,
                    ID=inner.InnerID,
                    scope=snippet_loc,
                    checksum=self.hashes_ossbom2midware(inner.InnerChecksum),
                    licenses=lic,
                    copyright=inner.Copyright,
                    external_references=self.exRefs_ossbom2midware(inner.InnerRef)
                )
                
                inner_valid = valid_info.get(inner.InnerID, None)
                if inner_valid:
                    comp.supplier = Spdx2Middleware.make_ind_or_comp_object(inner_valid.Supplier)
                    comp.originator = Spdx2Middleware.make_ind_or_comp_object(inner_valid.Originator)
                    comp.download_location = inner_valid.DownloadLocation
                    comp.source_repo = inner_valid.SourceRepository
                    comp.homepage = inner_valid.HomePage
                    comp.release_date = inner_valid.ReleaseTime
                    comp.built_date = inner_valid.BuiltTime
                    comp.valid_until_date = inner_valid.ValidUntilTime
                
                components.append(comp)
        
        if components:
            midware.components = components
        
        relations = []
        if bom.RelationshipInformation:
            for rel in bom.RelationshipInformation:
                if rel.Contain:
                    relations.append(
                        Relationship(
                            type="CONTAINS",
                            sourceID=rel.ResourceID,
                            targetID=rel.Contain
                        )
                    )
                elif rel.DependsOn:
                    relations.append(
                        Relationship(
                            type="DEPENDS_ON",
                            sourceID=rel.ResourceID,
                            targetID=rel.DependsOn
                        )
                    )
                elif rel.BuildDepends:
                    relations.append(
                        Relationship(
                            type="BUILD_DEPENDENCY_OF",
                            sourceID=rel.BuildDepends,
                            targetID=rel.ResourceID
                        )
                    )
            midware.relationship = relations
        
        if bom.Annotation:
            annotations = []
            for anno in bom.Annotation:
                annotations.append(
                    Annotation(
                        type="OTHER",
                        ID=anno.AnnotationID,
                        timestamp=anno.AnnotationTime,
                        annotator=[Individual(type='person', ID=anno.Annotator)],
                        text=anno.AnnotationText
                    )
                )
            midware.annotations = annotations
        
        properties = []
        if bom.ValidityInformation.DocumentValidationTime:
            properties.append(
                Extension(
                    key="DocumentValidationTime",
                    value=bom.ValidityInformation.DocumentValidationTime
                )
            )
        if bom.ValidityInformation.DocumentValidator:
            properties.append(
                Extension(
                    key="DocumentValidator",
                    value=bom.ValidityInformation.DocumentValidator
                )
            )
        midware.properties = properties if properties else None
        return midware
        
    def hashes_ossbom2midware(self, hashes: Optional[List[ossbom_model.Checksum]]) -> Optional[List[Hash]]:
        if not hashes:
            return None
        return [
            Hash(
                alg=hash.Algorithm,
                value=hash.Checksum
            ) for hash in hashes
        ]
    
    def exRefs_ossbom2midware(self, exRefs: Optional[List[ossbom_model.Reference]]) -> Optional[List[ExternalReference]]:
        if not exRefs:
            return None
        return [
            ExternalReference(
                type=ref.Name,
                url=ref.DocumentURI
            ) for ref in exRefs
        ]
        
    def make_midware_license(self, license: Optional[str], license_info: dict) -> Optional[License]:
        if not license:
            return None
        info = license_info.get(license, None)
        if license in [member.value for member in Schema]:
            lic = License(
                type="declared",
                spdxID=license
            )
        else:
            lic = License(
                type="declared",
                name=license
            )
        if info:
            lic.text = Text(
                contentType="text/plain",
                encoding="UTF-8",
                content=info.LicenseText
            )
            cross_ref = []
            if license.LicenseRef:
                for ref in license.LicenseRef:
                    cross_ref.append(
                        CrossRef(
                            url=ref.DocumentURI
                        )
                    )
                lic.crossRefs = cross_ref
        return lic
    
    def properties_ossbom2midware(self, properties: Optional[List[ossbom_model.Property]]) -> Optional[List[Extension]]:
        if not properties:
            return None
        return [Extension(
            key=prop.Key,
            value=prop.Value
        ) for prop in properties]


class Middleware2Ossbom:
    def __init__(self, midware: Middleware) -> None:
        self.midware = midware
    
    def middleware2ossbom(self) -> dict:
        doc_info = ossbom_model.DocumentInfo(
            DocumentFormat="OSSBOM",
            DocumentName=self.midware.doc_name,
            DocumentVersion="1.0",
            DocumentID=self.midware.doc_ID,
            DocumentLicense=self.license_midware2ossbom(self.midware.licenses),
            DocumentRef=self.exRefs_midware2ossbom(self.midware.external_references),
        )
        
        pkg = []
        inner = []
        licenses = []
        relations = []
        rs_valid = []
        if self.midware.components:
            for comp in self.midware.components:
                if comp.type.lower().startswith("package"):
                    pkg.append(
                        ossbom_model.PkgInfo(
                            PackageName=comp.name,
                            PackageVersion=comp.version,
                            PackageID=comp.ID,
                            PackageChecksum=self.checksum_midware2ossbom(comp.checksum),
                            DeclaredLicense=self.license_midware2ossbom(comp.licenses),
                            Copyright=comp.copyright,
                            Properties=self.properties_midware2ossbom(comp.properties),
                            PackageRef=self.exRefs_midware2ossbom(comp.external_references)
                        )
                    )
                elif comp.type.lower() in ["file", "snippet"]:
                    inner_loc = None
                    if comp.scope:
                        if not isinstance(comp.scope, str):
                            for snp_scope in comp.scope:
                                inner_loc = snp_scope.fromFile + "<L>" + str(snp_scope.startPointer.offset) + ":" + str(snp_scope.endPointer.offset)
                    inner.append(
                        ossbom_model.InnerInfo(
                            InnerType=comp.type.upper(),
                            InnerName=comp.name,
                            InnerID=comp.ID,
                            InnerLocation=inner_loc,
                            InnerChecksum=self.checksum_midware2ossbom(comp.checksum),
                            DeclaredLicense=self.license_midware2ossbom(comp.licenses),
                            Copyright=comp.copyright,
                            InnerRef=self.exRefs_midware2ossbom(comp.external_references)
                        )
                    )
                if comp.supplier or comp.originator or comp.download_location or comp.source_repo or comp.homepage or comp.release_date or comp.built_date or comp.valid_until_date:
                    supplier = Middleware2Spdx.individual2str([comp.supplier])
                    originator = Middleware2Spdx.individual2str(comp.originator)
                    if supplier:
                        supplier = supplier[0]
                    if originator:
                        originator = originator[0]
                    rs_valid.append(
                        ossbom_model.ResourceValidity(
                            ResourceID=comp.ID,
                            Supplier=supplier,
                            Originator=originator,
                            DownloadLocation=comp.download_location,
                            SourceRepository=comp.source_repo,
                            HomePage=comp.homepage,
                            ReleaseTime=comp.release_date,
                            BuiltTime=comp.built_date,
                            ValidUntilTime=comp.valid_until_date
                        )
                    )
                if comp.licenses:
                    for lic in comp.licenses:
                        if not lic.spdxID and not lic.name:
                            continue
                        if lic.spdxID:
                            licenses.append(
                                ossbom_model.License(
                                    LicenseID=lic.spdxID,
                                    LicenseName=lic.name,
                                    LicenseText=lic.text.content if lic.text else None,
                                    LicenseRef=[ossbom_model.Reference(Name="LicenseRef", DocumentURI=ref.url) for ref in lic.crossRefs] if lic.crossRefs else None
                                )
                            )
                        else:
                            licenses.append(
                                ossbom_model.License(
                                    LicenseID=lic.name,
                                    LicenseText=lic.text.content if lic.text else None,
                                    LicenseRef=[ossbom_model.Reference(Name="LicenseRef", DocumentURI=ref.url) for ref in lic.crossRefs] if lic.crossRefs else None
                                )
                            )
            
        if self.midware.relationship:
            for rel in self.midware.relationship:
                if rel.type == "CONTAINS":
                    relations.append(
                        ossbom_model.RelationshipInfo(
                            ResourceID=rel.sourceID,
                            Contain=rel.targetID
                        )
                    )
                elif rel.type == "DEPENDS_ON":
                    relations.append(
                        ossbom_model.RelationshipInfo(
                            ResourceID=rel.sourceID,
                            DependsOn=rel.targetID
                        )
                    )
                elif rel.type == "DEPENDENCY_OF":
                    relations.append(
                        ossbom_model.RelationshipInfo(
                            ResourceID=rel.targetID,
                            DependsOn=rel.sourceID
                        )
                    )
                elif rel.type == "BUILD_DEPENDENCY_OF":
                    relations.append(
                        ossbom_model.RelationshipInfo(
                            ResourceID=rel.sourceID,
                            BuildDepends=rel.targetID
                        )
                    )
        
        annotations = []
        if self.midware.annotations:
            for anno in self.midware.annotations:
                annotator = None
                if anno.annotator:
                    annotator = Middleware2Spdx.individual2str(anno.annotator)
                    if annotator:
                        annotator = annotator[0]
                annotations.append(
                    ossbom_model.Annotations(
                        AnnotationID=anno.ID,
                        AnnotationTime=anno.timestamp,
                        Annotator=annotator,
                        AnnotationText=anno.text
                    )
                )
        
        creator = Middleware2Spdx.individual2str(self.midware.creator)
        if creator:
            creator = creator[0]
        
        doc_valid_time = Middleware2Spdx.match_property("DocumentValidationTime", self.midware.properties)
        if doc_valid_time:
            doc_valid_time = doc_valid_time[0]
        
        doc_validator = Middleware2Spdx.match_property("DocumentValidator", self.midware.properties)
        if doc_validator:
            doc_validator = doc_validator[0]
        
        valid_info = ossbom_model.ValidityInfo(
            DocumentCreationTime=self.midware.timestamp,
            DocumentCreator=creator,
            LicenseListVersion=self.midware.license_list_version,
            DocumentValidationTime=doc_valid_time,
            DocumentValidator=doc_validator,
            ResourceValidityInfo=rs_valid if rs_valid else None,
        )
        
        bom = ossbom_model.OSSBOM(
            DocumentInformation=doc_info,
            PackageInformation=pkg if pkg else None,
            InnerInformation=inner if inner else None,
            ValidityInformation=valid_info,
            RelationshipInformation=relations if relations else None,
            OtherLicensingInformation=licenses if licenses else None,
            Annotation=annotations if annotations else None
        )
        return bom.model_dump(mode='json', exclude_none=True)
    
    def properties_midware2ossbom(self, properties: Optional[List[Extension]]) -> Optional[List[ossbom_model.Property]]:
        if not properties:
            return None
        return [
            ossbom_model.Property(
                Key=prop.key,
                Value=prop.value
            )
            for prop in properties
        ]
    
    def checksum_midware2ossbom(self, checksum: Optional[List[Hash]]) -> Optional[List[ossbom_model.Checksum]]:
        if not checksum:
            return None
        return [
            ossbom_model.Checksum(
                Algorithm=hash.alg,
                Checksum=hash.value
            )
            for hash in checksum
        ]
    
    def license_midware2ossbom(self, license: Optional[List[License]]) -> Optional[str]:
        if not license:
            return None
        if license[0].spdxID:
            return license[0].spdxID
        else:
            return license[0].name
    
    def exRefs_midware2ossbom(self, exRefs: Optional[List[ExternalReference]]) -> Optional[List[ossbom_model.Reference]]:
        if not exRefs:
            return None
        return [
            ossbom_model.Reference(
                Name=ref.type,
                DocumentURI=ref.url
            ) for ref in exRefs
        ]


if __name__ == "__main__":
    import json
    examples = [
        "/home/jcg/SBOM/sbom-generator/SIT/result/linuxsbom.json",
    ]
    for path in examples:
        bom = json.load(open(path, "r"))
        ossbom = Ossbom2Middleware(bom).ossbom2middleware()
        json.dump(ossbom.model_dump(exclude_none=True), open("/home/jcg/SBOM/sbom-generator/SIT/output/midware.json", "w"), indent=4)
        midware = json.load(open("/home/jcg/SBOM/sbom-generator/SIT/output/midware.json", "r"))
        Middleware2Ossbom(Middleware(**midware)).middleware2ossbom()