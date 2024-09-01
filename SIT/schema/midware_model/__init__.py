from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Literal, Union


class Extension(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    key: str = Field(
        ...,
        description='The name of the Extension',
        title='Key',
    )
    value: Optional[str] = Field(
        None, 
        description='The value of the Extension',
        title='Value',
    )

class Hash(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    alg: str = Field(
        ...,
        description='The algorithm used to compute the hash',
        title='Algorithm',
    )
    value: str = Field(
        ...,
        description='The hash value',
        title='Value',
    )

class ExternalReference(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    url: str = Field(
        ...,
        description='URL(or URN) of the external reference',
        title='URL',
    )
    comment: Optional[str] = Field(
        None,
        description='Comment on the external reference',
        title='Comment',
    )
    type: str = Field(
        ...,
        description='Type of the external reference',
        title='Type',
    )
    checksum: Optional[List[Hash]] = Field(
        None, 
        description='Checksum of the external reference',
        title='Checksum',
    )

class Individual(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: Literal["organization", "person"] = Field(
        ...,
        description='The type of the individual',
        title='Type',
    )
    ID: Optional[str] = Field(
        None,
        description='The identifier of the individual',
        title='ID',
    )
    name: Optional[str] = Field(
        None,
        description='The name of the individual',
        title='Name',
    )
    email: Optional[str] = Field(
        None,
        description='The email of the individual',
        title='Email',
    )
    phone: Optional[str] = Field(
        None,
        description='The phone number of the individual',
        title='Phone',
    )
    address: Optional[str] = Field(
        None,
        description='The address of the individual',
        title='Address',
    )
    url: Optional[List[str]] = Field(
        None,
        description='The URL of the individual',
        title='URL',
    )
    contacts: Optional[List["Individual"]] = Field(
        None,
        description='The contacts of the individual',
        title='Contacts',
    )

class Text(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    contentType: Optional[str] = Field(
        'text/plain',
        description='The content type of the text',
        title='Content-Type',
    )
    encoding: Optional[str] = Field(
        None,
        description='The encoding of the text',
        title='Encoding',
    )   
    content: str = Field(
        ...,
        description='The content of the text',
        title='Content',
    )

class Swid(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    tagID: str = Field(
        ...,
        description='The tag ID of the SWID',
        title='Tag ID',
    )
    name: str = Field(
        ...,
        description='The name of the SWID',
        title='Name',
    )
    version: Optional[str] = Field(
        '0.0',
        description='The version of the SWID',
        title='Version',
    )
    tagVersion: Optional[int] = Field(
        0,
        description='The tag version of the SWID',
        title='Tag Version',
    )
    patch: Optional[bool] = Field(
        False,
        description='The patch of the SWID',
        title='Patch',
    )
    text: Optional[Text] = Field(
        None,
        description='Describe the metadata and content of the SWID',
        title='Text',
    )
    url: Optional[str] = Field(
        None,
        description='The URL of the SWID File',
        title='URL',
    )

class Note(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    locale: Optional[str] = Field(
        None,
        description='The ISO-639 (or higher) language code and optional ISO-3166 (or higher) country code. Examples include: "en", "en-US", "fr" and "fr-CA"',
        title='Locale',
    )
    text: Text = Field(
        ...,
        description='Content of the Release Note.',
        title='Release Note Content',
    )

class Issue(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: str = Field(
        ...,
        description='The type of the issue.',
        title='Type',
    )
    id: Optional[str] = Field(
        None,
        description='The identifier of the issue.',
        title='ID',
    )
    name: Optional[str] = Field(
        None,
        description='The name of the issue.',
        title='Name',
    )
    description: Optional[str] = Field(
        None,
        description='The description of the issue.',
        title='Description',
    )
    source: Optional[Extension] = Field(
        None,
        description='Source references to the issue',
        title='Source References',
    )
    url_refs: Optional[List[str]] = Field(
        None, 
        description='Reference URLs to the issue',
        title='References',
    )

class ReleaseNotes(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: str = Field(
        ...,
        description='The software versioning type the release note describes.',
        title='Type',
    )
    title: Optional[str] = Field(
        None,
        description='The title of the release note.',
        title='Title',
    )
    featuredImage: Optional[str] = Field(
        None,
        description='The URL of the featured image for the release note.',
        title='Featured Image',
    )
    socialImage: Optional[str] = Field(
        None,
        description='The URL of the social image for the release note.',
        title='Social Image',
    )
    description: Optional[str] = Field(
        None,
        description='The description of the release.',
        title='Description',
    )
    timestamp: Optional[str] = Field(
        None,
        description='The timestamp of the release.',
        title='Timestamp',
    )
    aliases: Optional[List[str]] = Field(
        None,
        description='The other names of the release.',
        title='Aliases',
    )
    tags: Optional[List[str]] = Field(
        None,
        description='The tags of the release.',
        title='Tags',
    )
    resolves: Optional[List[Issue]] = Field(
        None,
        description='The issues resolved by the release.',
        title='Resolves',
    )
    notes: Optional[List[Note]] = Field(
        None,
        description='Notes containing the locale and content.',
        title='Notes',
    )
    properties: Optional[List[Extension]] = Field(
        None,
        description='The properties of the release.',
        title='Properties',
    )

class Licensing(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    altIds: Optional[List[str]] = Field(
        None,
        description='License identifiers that may be used to manage licenses and their lifecycle',
        title='Alternate License Identifiers',
    )
    licensor: Optional[List[Individual]] = Field(
        None,
        description='The individual or organization that grants a license to another individual or organization',
        title='Licensor',
    )
    licensee: Optional[List[Individual]] = Field(
        None,
        description='The individual or organization for which a license was granted to',
        title='Licensee',
    )
    purchaser: Optional[List[Individual]] = Field(
        None,
        description='The individual or organization that purchased the license',
        title='Purchaser',
    )
    purchaseOrder: Optional[str] = Field(
        None,
        description='The purchase order identifier the purchaser sent to a supplier or vendor to authorize a purchase',
        title='Purchase Order',
    )
    licenseTypes: Optional[List[str]] = Field(
        None,
        description='The type of license(s) that was granted to the licensee.',
        title='License Type',
    )
    lastRenewal: Optional[str] = Field(
        None,
        description='The timestamp indicating when the license was last renewed. For new purchases, this is often the purchase or acquisition date. For non-perpetual licenses or subscriptions, this is the timestamp of when the license was last renewed.',
        title='Last Renewal',
    )
    expiration: Optional[str] = Field(
        None,
        description='The timestamp indicating when the current license expires (if applicable).',
        title='Expiration',
    )

class CrossRef(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    isLive: Optional[bool] = Field(
        None,
        description='Indicate a URL is still a live accessible location on the public internet',
        title='Is Live',
    )
    isValid: Optional[bool] = Field(
        None, 
        description='True if the URL is a valid well formed URL',
        title='Is Valid',
    )
    isWayBackLink: Optional[bool] = Field(
        None, 
        description='True if the License SeeAlso URL points to a Wayback archive',
        title='Is Wayback Link',
    )
    match: Optional[str] = Field(
        None,
        description='Status of a License List SeeAlso URL reference if it refers to a website that matches the license text.',
        title='Match',
    )
    order: Optional[int] = Field(
        None, 
        description='The ordinal order of this element within a list',
        title='Order',
    )
    timestamp: Optional[str] = Field(
        None, 
        description='Timestamp',
        title='Timestamp',
    )
    url: str = Field(
        ..., 
        description='URL Reference',
        title='URL',
    )

class License(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: Optional[Literal["declared", "concluded"]] = Field(
        None,
        description='The type of the license',
        title='Type',
    )
    spdxID: Optional[str] = Field(
        None,
        description='The SPDX identifier of the license',
        title='SPDX ID',
    )
    name: Optional[str] = Field(
        None,
        description='The name of the license',
        title='Name',
    )
    text: Optional[Text] = Field(
        None,
        description='The text of the license',
        title='Text',
    )
    licensing: Optional[Licensing] = Field(
        None,
        description='The licensing information of the license',
        title='Licensing',
    )
    crossRefs: Optional[List[CrossRef]] = Field(
        None, 
        description='Cross Reference Detail for a license SeeAlso URL',
        title='Cross References',
    )
    properties: Optional[List[Extension]] = Field(
        None,
        description='The properties of the license',
        title='Properties',
    )

class SnippetPointer(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    offset: Optional[int] = Field(
        None, 
        description='Byte offset in the file',
        title='Offset'
    )
    lineNumber: Optional[int] = Field(
        None, 
        description='line number offset in the file',
        title='Line Number'
    )

class SnippetScope(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    endPointer: SnippetPointer = Field(
        ...,
        description='End Pointer of a Snippet',
        title='End Pointer'
    )
    startPointer: SnippetPointer = Field(
        ...,
        description='Start Pointer of a Snippet',
        title='Start Pointer',
    )
    fromFile: str = Field(
        ...,
        description='File from which the snippet is extracted',
        title='From File',
    )

class Signer(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    algorithm: str = Field(
        ...,
        description='The algorithm used to generate the signature.',
        title='Algorithm',
    )
    keyId: Optional[str] = Field(
        None,
        description='Optional. Application specific string identifying the signature key.',
        title='Key ID',
    )
    publicKey: Optional[str] = Field(
        None, 
        description='Optional. Public key object.', 
        title='Public key'
    )
    certificatePath: Optional[List[str]] = Field(
        None,
        description='Optional. Sorted array of X.509 [RFC5280] certificates, where the first element must contain the signature certificate. The certificate path must be contiguous but is not required to be complete.',
        title='Certificate path',
    )
    excludes: Optional[List[str]] = Field(
        None,
        description='Optional. Array holding the names of one or more application level properties that must be excluded from the signature process. Note that the "excludes" property itself, must also be excluded from the signature process. Since both the "excludes" property and the associated data it points to are unsigned, a conforming JSF implementation must provide options for specifying which properties to accept.',
        title='Excludes',
    )
    value: str = Field(
        ...,
        description='The signature data. Note that the binary representation must follow the JWA [RFC7518] specifications.',
        title='Signature',
    )

class Signature(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: Optional[str] = Field(
        None,
        description='The type of the signature.',
        title='Type',
    )
    sigs: Optional[List[Signer]] = Field(
        None,
        description='Array of signer objects.',
        title='Signers',
    )

class Component(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: Optional[str] = Field(
        None,
        description='The type of the component',
        title='Type',
    )
    mime_type: Optional[str] = Field(
        None,
        description='The MIME type of the component',
        title='MIME Type',
    )
    name: str = Field(
        ...,
        description='The name of the component',
        title='Name',
    )
    version: Optional[str] = Field(
        None,
        description='The version of the component',
        title='Version',
    )
    ID: Optional[str] = Field(
        None,
        description='The identifier of the component',
        title='ID',
    )
    scope: Optional[Union[Literal['required', 'optional', 'excluded'], List[SnippetScope]]] = Field(
        None,
        description='The scope of the component',
        title='Scope',
    )
    originator: Optional[List[Individual]] = Field(
        None,
        description='The originator of the component',
        title='Originator',
    )
    supplier: Optional[Individual] = Field(
        None,
        description='The supplier of the component',
        title='Supplier',
    )
    publisher: Optional[Individual] = Field(
        None,
        description='The publisher of the component',
        title='Publisher',
    )
    group: Optional[str] = Field(
        None,
        description='The group of the component',
        title='Group',
    )
    purl: Optional[str] = Field(
        None,
        description='The package URL of the component',
        title='Package URL',
    )
    cpe: Optional[str] = Field(
        None,
        description='The Common Platform Enumeration of the component',
        title='Common Platform Enumeration',
    )
    omniborId: Optional[List[str]] = Field(
        None,
        description='The OmniBOR Artifact ID of the component',
        title='OmniBOR Artifact ID',
    )
    swhid: Optional[List[str]] = Field(
        None,
        description='The Software Heritage persistent ID of the component',
        title='Software Heritage Persistent ID',
    )
    swid: Optional[Swid] = Field(
        None,
        description='The Software Identification Tag of the component',
        title='Software Identification Tag',
    )
    licenses: Optional[List[License]] = Field(
        None,
        description='The licenses of the component',
        title='Licenses',
    )
    copyright: Optional[str] = Field(
        None,
        description='The copyright of the component',
        title='Copyright',
    )
    checksum: Optional[List[Hash]] = Field(
        None,
        description='The checksum of the component',
        title='Checksum',
    )
    external_references: Optional[List[ExternalReference]] = Field(
        None,
        description='The external references of the component',
        title='External References',
    )
    verificationCodeExcludedFiles: Optional[List[str]] = Field(
        None,
        description='The excluded files of the verification code',
        title='Files that were excluded when calculating the verification code',
    )
    verificationCodeValue: Optional[str] = Field(
        None,
        description='The verification code value',
        title='Verification Code Value',
    )
    download_location: Optional[str] = Field(
        None,
        description='The download location of the component',
        title='Download Location',
    )
    source_repo: Optional[str] = Field(
        None,
        description='The source repository of the component',
        title='Source Repository',
    )
    homepage: Optional[str] = Field(
        None,
        description='The homepage of the component',
        title='Homepage',
    )
    source_info: Optional[str] = Field(
        None,
        description='The source information of the component',
        title='Source Information',
    )
    description: Optional[str] = Field(
        None,
        description='The description of the component',
        title='Description',
    )
    built_date: Optional[str] = Field(
        None,
        description='The built date of the component',
        title='Built Date',
    )
    release_date: Optional[str] = Field(
        None,
        description='The release date of the component',
        title='Release Date',
    )
    valid_until_date: Optional[str] = Field(
        None,
        description='The valid until date of the component',
        title='Valid Until Date',
    )
    releaseNotes: Optional[ReleaseNotes] = Field(
        None,
        description='The release notes of the component',
        title='Release Notes',
    )
    tags: Optional[List[str]] = Field(
        None,
        description='The tags of the component',
        title='Tags',
    )
    signature: Optional[Signature] = Field(
        None,
        description='Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).',
        title='Signature',
    )
    properties: Optional[List[Extension]] = Field(
        None,
        description='The properties of the component',
        title='Properties',
    )

class Service(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    ID: Optional[str] = Field(
        None,
        description="An optional identifier which can be used to reference the service elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.",
        title='BOM Reference',
    )
    provider: Optional[Individual] = Field(
        None,
        description='The organization that provides the service.',
        title='Provider',
    )
    group: Optional[str] = Field(
        None,
        description='The grouping name, namespace, or identifier. This will often be a shortened, single name of the company or project that produced the service or domain name. Whitespace and special characters should be avoided.',
        examples=['com.acme'],
        title='Service Group',
    )
    name: str = Field(
        ...,
        description='The name of the service. This will often be a shortened, single name of the service.',
        examples=['ticker-service'],
        title='Service Name',
    )
    version: Optional[str] = Field(
        None, description='The service version.', title='Service Version'
    )
    description: Optional[str] = Field(
        None,
        description='Specifies a description for the service',
        title='Service Description',
    )
    endpoints: Optional[List[str]] = Field(
        None,
        description='The endpoint URIs of the service. Multiple endpoints are allowed.',
        examples=['https://example.com/api/v1/ticker'],
        title='Endpoints',
    )
    authenticated: Optional[bool] = Field(
        None,
        description='A boolean value indicating if the service requires authentication. A value of true indicates the service requires authentication prior to use. A value of false indicates the service does not require authentication.',
        title='Authentication Required',
    )
    x_trust_boundary: Optional[bool] = Field(
        None,
        alias='x-trust-boundary',
        description='A boolean value indicating if use of the service crosses a trust zone or boundary. A value of true indicates that by using the service, a trust boundary is crossed. A value of false indicates that by using the service, a trust boundary is not crossed.',
        title='Crosses Trust Boundary',
    )
    trustZone: Optional[str] = Field(
        None,
        description='The name of the trust zone the service resides in.',
        title='Trust Zone',
    )
    data: Optional[List[str]] = Field(
        None,
        description='Specifies information about the data including the directional flow of data and the data classification.',
        title='Data',
    )
    licenses: Optional[List[License]] = Field(
        None, 
        title='Component License(s)'
    )
    externalReferences: Optional[List[ExternalReference]] = Field(
        None,
        description='External references provide a way to document systems, sites, and information that may be relevant but are not included with the BOM. They may also establish specific relationships within or external to the BOM.',
        title='External References',
    )
    services: Optional[List["Service"]] = Field(
        None,
        description='A list of services included or deployed behind the parent service. This is not a dependency tree. It provides a way to specify a hierarchical representation of service assemblies.',
        title='Services',
    )
    releaseNotes: Optional[ReleaseNotes] = Field(
        None, description='Specifies optional release notes.', title='Release notes'
    )
    properties: Optional[List[Extension]] = Field(
        None,
        description='Provides the ability to document properties in a name-value store.',
        title='Properties',
    )
    tags: Optional[str] = Field(
        None, 
        title='Tags',
        description='Provides a way to categorize or classify services. Tags are free-form and can be used to group services in a way that is meaningful to the organization.',
    )
    signature: Optional[Signature] = Field(
        None,
        description='Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).',
        title='Signature',
    )

class Relationship(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: str = Field(
        ...,
        description='The type of the relationship',
        title='Type',
    )
    sourceID: str = Field(
        ...,
        description='The source ID of the relationship',
        title='Source ID',
    )
    targetID: str = Field(
        ...,
        description='The target ID of the relationship',
        title='Target ID',
    )
    comment: Optional[str] = Field(
        None, 
        description='The comment of the relationship',
        title='Comment',
    )

class Annotation(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    type: str = Field(
        ...,
        description='The type of the annotation',
        title='Type',
    )
    ID: Optional[str] = Field(
        None,
        description='The identifier of the annotation',
        title='ID',
    )
    subjects: List[str] = Field(
        ...,
        description='The subjects of the annotation',
        title='Subjects',
    )
    timestamp: str = Field(
        ...,
        description='The timestamp of the annotation',
        title='Timestamp',
    )
    annotator: List[Union[Individual, Component, Service]] = Field(
        ...,
        description='The annotator of the annotation',
        title='Annotator',
    )
    text: str = Field(
        ...,
        description='The text of the annotation',
        title='Text',
    )
    signature: Optional[Signature] = Field(
        None,
        description='Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).',
        title='Signature',
    )

class Middleware(BaseModel):
    type: Literal["Middleware"] = Field(
        "Middleware",
        description='Indicate the middleware type',
        title='Type',
    )
    bom_version: Optional[int] = Field(
        1,
        description='The version of the SBOM',
        title='BOM Version',
    )
    doc_ID: str = Field(
        ...,
        description='The identifier of the document',
        title='Document ID',
    )
    doc_name: str = Field(
        ...,
        description='The name of the document',
        title='Document Name',
    )
    doc_namespace: str = Field(
        ...,
        description='The namespace of the document',
        title='Document Namespace',
    )
    license_list_version: Optional[str] = Field(
        None,
        description='The version of the license list',
        title='License List Version',
    )
    lifecycles: Optional[List[str]] = Field(
        None,
        description='The lifecycles of the document',
        title='Lifecycles',
    )
    timestamp: str = Field(
        ...,
        description='The timestamp of the document',
        title='Timestamp',
    )
    licenses: List[License] = Field(
        ...,
        description='The licenses of the document',
        title='Licenses',
    )
    creator: List[Union[Individual, Component, Service]] = Field(
        None,
        description='The creator of the document',
        title='Creator',
    )
    components: Optional[List[Component]] = Field(
        None,
        description='The components of the document',
        title='Components',
    )
    relationship: Optional[List[Relationship]] = Field(
        None,
        description='The relationships between the components',
        title='Relationships',
    )
    properties: Optional[List[Extension]] = Field(
        None,
        description='The properties of the document',
        title='Properties',
    )
    external_references: Optional[List[ExternalReference]] = Field(
        None,
        description='The external references of the document',
        title='External References',
    )
    annotations: Optional[List[Annotation]] = Field(
        None,
        description='The annotations of the document',
        title='Annotations',
    )
    signature: Optional[Signature] = Field(
        None,
        description='Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).',
        title='Signature',
    )

