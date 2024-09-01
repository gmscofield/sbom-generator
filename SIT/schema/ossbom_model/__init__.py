from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Literal


class Reference(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    Name: str = Field(
        ...,
        title="Reference Name",
        description="The name of the reference."
    )
    DocumentURI: str = Field(
        ...,
        title="Document URI",
        description="The URI of the document."
    )

class Property(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    Key: str = Field(
        ...,
        title="Property Name",
        description="The name of the property."
    )
    Value: str = Field(
        ...,
        title="Property Value",
        description="The value of the property."
    )

class Checksum(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    Algorithm: str = Field(
        ...,
        title="Checksum Algorithm",
        description="The algorithm of the checksum."
    )
    Checksum: str = Field(
        ...,
        title="Checksum Value",
        description="The value of the checksum."
    )

class DocumentInfo(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    DocumentFormat: str = Field(
        "OSSBOM",
        title="Document Format",
        description="The format of the document."
    )
    DocumentName: str = Field(
        ...,
        title="Document Name",
        description="The name of the document."
    )
    DocumentVersion: str = Field(
        ...,
        title="Document Version",
        description="The version of the document."
    )
    DocumentID: str = Field(
        ...,
        title="Document ID",
        description="The ID of the document."
    )
    DocumentLicense: str = Field(
        "CC0-1.0",
        title="Document License",
        description="The license of the document."
    )
    DocumentRef: Optional[List[Reference]] = Field(
        None,
        title="Document Reference",
        description="The reference of the document."
    )

class PkgInfo(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    PackageName: str = Field(
        ...,
        title="Package Name",
        description="The name of the package."
    )
    PackageVersion: Optional[str] = Field(
        None,
        title="Package Version",
        description="The version of the package."
    )
    PackageID: str = Field(
        ...,
        title="Package ID",
        description="The ID of the package."
    )
    PackageChecksum: Optional[List[Checksum]] = Field(
        None,
        title="Package Checksum",
        description="The checksum of the package."
    )
    DeclaredLicense: Optional[str] = Field(
        None,
        title="Declared License",
        description="The declared license of the package."
    )
    Copyright: Optional[str] = Field(
        None,
        title="Copyright",
        description="The copyright of the package."
    )
    Properties: Optional[List[Property]] = Field(
        None,
        title="Properties",
        description="The properties of the package."
    )
    PackageRef: Optional[List[Reference]] = Field(
        None,
        title="Package Reference",
        description="The reference of the package."
    )

class InnerInfo(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    InnerType: Literal['FILE', 'SNIPPET'] = Field(
        ...,
        title="Inner Type",
        description="The type of the inner information."
    )
    InnerName: str = Field(
        ...,
        title="Inner Name",
        description="The name of the inner information."
    )
    InnerID: str = Field(
        ...,
        title="Inner ID",
        description="The ID of the inner information."
    )
    InnerLocation: Optional[str] = Field(
        None,
        title="Inner Location",
        description="The location of the inner information."
    )
    InnerChecksum: Optional[List[Checksum]] = Field(
        None,
        title="Inner Checksum",
        description="The checksum of the inner information."
    )
    DeclaredLicense: Optional[str] = Field(
        None,
        title="Declared License",
        description="The declared license of the inner information."
    )
    Copyright: Optional[str] = Field(
        None,
        title="Copyright",
        description="The copyright of the inner information."
    )
    InnerRef: Optional[List[Reference]] = Field(
        None,
        title="Inner Reference",
        description="The reference of the inner information."
    )

class ResourceValidity(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    ResourceID: str = Field(
        ...,
        title="Resource ID",
        description="The ID of the resource."
    )
    Supplier: Optional[str] = Field(
        None,
        title="Supplier",
        description="The supplier of the resource."
    )
    Originator: Optional[str] = Field(
        None,
        title="Originator",
        description="The originator of the resource."
    )
    DownloadLocation: Optional[str] = Field(
        None,
        title="Download Location",
        description="The download location of the resource."
    )
    SourceRepository: Optional[str] = Field(
        None,
        title="Source Repository",
        description="The source repository of the resource."
    )
    HomePage: Optional[str] = Field(
        None,
        title="Home Page",
        description="The home page of the resource."
    )
    ReleaseTime: Optional[str] = Field(
        None,
        title="Release Time",
        description="The release time of the resource."
    )
    BuiltTime: Optional[str] = Field(
        None,
        title="Built Time",
        description="The built time of the resource."
    )
    ValidUntilTime: Optional[str] = Field(
        None,
        title="Valid Until Time",
        description="The valid until time of the resource."
    )

class ValidityInfo(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    DocumentCreator: str = Field(
        ...,
        title="Document Creator",
        description="The creator of the document."
    )
    DocumentCreationTime: str = Field(
        ...,
        title="Document Creation Time",
        description="The creation time of the document."
    )
    LicenseListVersion: str = Field(
        ...,
        title="License List Version",
        description="The version of the license list."
    )
    DocumentValidator: Optional[str] = Field(
        None,
        title="Document Validator",
        description="The validator of the document."
    )
    DocumentValidationTime: Optional[str] = Field(
        None,
        title="Document Validation Time",
        description="The validation time of the document."
    )
    ResourceValidityInfo: Optional[List[ResourceValidity]] = Field(
        None,
        title="Resource Validity Information",
        description="The validity information of the resource."
    )

class RelationshipInfo(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    ResourceID: str = Field(
        ...,
        title="Resource ID",
        description="The ID of the resource."
    )
    Contain: Optional[str] = Field(
        None,
        title="Contain",
        description="The contained resources."
    )
    DependsOn: Optional[str] = Field(
        None,
        title="Depends On",
        description="The depended resources."
    )
    BuildDepends: Optional[str] = Field(
        None,
        title="Build Depends",
        description="The build depended resources."
    )

class License(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    LicenseID: Optional[str] = Field(
        ...,
        title="License ID",
        description="The ID of the license."
    )
    LicenseName: Optional[str] = Field(
        None,
        title="License Name",
        description="The name of the license."
    )
    LicenseText: Optional[str] = Field(
        None,
        title="License Text",
        description="The text of the license."
    )
    LicenseChecksum: Optional[Checksum] = Field(
        None,
        title="License Checksum",
        description="The checksum of the license."
    )
    LicenseRef: Optional[List[Reference]] = Field(
        None,
        title="License Reference",
        description="The reference of the license."
    )

class Annotations(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    AnnotationID: str = Field(
        ...,
        title="Annotation ID",
        description="The ID of the annotation."
    )
    AnnotationTime: str = Field(
        ...,
        title="Annotation Time",
        description="The time of the annotation."
    )
    Annotator: str = Field(
        ...,
        title="Annotator",
        description="The annotator of the annotation."
    )
    AnnotationText: str = Field(
        ...,
        title="Annotation Text",
        description="The text of the annotation."
    )

class OSSBOM(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    DocumentInformation: DocumentInfo = Field(
        ...,
        title="Document Information",
        description="The document information section of the OSSBOM."
    )
    PackageInformation: Optional[List[PkgInfo]] = Field(
        None,
        title="Package Information",
        description="The package information section of the OSSBOM."
    )
    InnerInformation: Optional[List[InnerInfo]] = Field(
        None,
        title="Inner Information",
        description="The file and snippet information section of the OSSBOM."
    )
    ValidityInformation: ValidityInfo = Field(
        ...,
        title="Validity Information",
        description="The validity information section of the OSSBOM."
    )
    RelationshipInformation: Optional[List[RelationshipInfo]] = Field(
        None,
        title="Relationship Information",
        description="The relationship information section of the OSSBOM."
    )
    OtherLicensingInformation: Optional[List[License]] = Field(
        None,
        title="Other Licensing Information",
        description="The other licensing information section of the OSSBOM."
    )
    Annotation: Optional[List[Annotations]] = Field(
        None,
        title="Annotation",
        description="The annotation section of the OSSBOM."
    )


if __name__ == "__main__":
    import json
    # model_schema = OSSBOM.model_json_schema()
    # json.dump(model_schema, open("/home/jcg/SBOM/sbom-generator/SIT/schema/ossbom_model/ossbom.schema.json", "w"), indent=4)
    bom = json.load(open("/home/jcg/SBOM/sbom-generator/SIT/result/linuxsbom.json", "r"))
    OSSBOM(**bom)
    
    