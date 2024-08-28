# import sys
# sys.path.append("/home/jcg/SBOM/sbom-generator/SbomGT/")

from .middleware import Middleware, Component, Licensing, CrossRef, Service, Signer, Signature, ReleaseNotes, Relationship, Hash, Annotation, License, Individual, Extension, ExternalReference, Issue, Note, Text, Swid
from ..schema import cdx_model
from typing import Union, List, Optional, Tuple
from datetime import datetime
import pydantic
import json
import logging
import re

class Cdx2Middleware:
    def __init__(self, cdx_bom: dict) -> None:
        if cdx_bom.get("specVersion") != "1.6":
            raise ValueError("Only support CycloneDX 1.6 version")
        self.cdx_bom = cdx_bom

    def cdx2middleware(self) -> Middleware:
        bom = cdx_model.CyclonedxBillOfMaterialsStandard(**self.cdx_bom)
        bom_license = None
        timestamp = None
        lfc = None
        properties = []
        components = []
        relations = []
        creators = []
        if bom.metadata:
            timestamp = bom.metadata.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if bom.metadata.timestamp else None
            bom_license = self.license_cdx2mid(bom.metadata.licenses)
            if bom.metadata.lifecycles:
                lfc = []
                for lfcycle in bom.metadata.lifecycles:
                    if isinstance(lfcycle, cdx_model.Lifecycles):
                        lfc.append(lfcycle.phase.value)
                    elif isinstance(lfcycle, cdx_model.Lifecycles1):
                        lf_str = f"name: {lfcycle.name}"
                        if lfcycle.description:
                            lf_str += f"; description: {lfcycle.description}"
                        lfc.append(lf_str)
            
            if bom.metadata.tools:
                print(bom.metadata.tools)
                if isinstance(bom.metadata.tools, cdx_model.Tools):
                    if bom.metadata.tools.components:
                        for comp in bom.metadata.tools.components:
                            cp, _ = self.component_cdx2mid(comp)
                            creators.append(cp[-1])
                    if bom.metadata.tools.services:
                        for serve in bom.metadata.tools.services:
                            creators.append(
                                self.service_cdx2mid(serve)
                            )
                else:
                    for tool in bom.metadata.tools:
                        creators.append(
                            Component(
                                name=tool.name,
                                version=tool.version.root if tool.version else None,
                                originator=Individual(
                                    type="person",
                                    name=tool.vendor
                                ),
                                checksum=self.hash_cdx2mid(tool.hashes),
                                external_references=self.exRef_cdx2mid(tool.externalReferences),
                            )
                        )
            
            if bom.metadata.manufacturer:
                creators.append(self.entity_contact2individual(bom.metadata.manufacturer))
            
            if bom.metadata.authors:
                for author in bom.metadata.authors:
                    creators.append(self.entity_contact2individual(author))
            
            if bom.metadata.manufacture:
                creators.append(self.entity_contact2individual(bom.metadata.manufacture))
            
            if bom.metadata.component:
                meta_comp, meta_relation = self.component_cdx2mid(bom.metadata.component)
                components.extend(meta_comp)
                relations.extend(meta_relation)
            
            if bom.metadata.supplier:
                components[-1].supplier = self.entity_contact2individual(bom.metadata.supplier)
            
            if bom.metadata.properties:
                meta_properties = self.property_cdx2mid(bom.metadata.properties)
                if meta_properties:
                    properties.extend(meta_properties)
        
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        if not bom_license:
            bom_license = [
                License(
                    type="declared",
                    spdxID="CC0-1.0"
                )
            ]
        
        if bom.components:
            for comp in bom.components:
                mid_comp, mid_relations = self.component_cdx2mid(comp)
                components.extend(mid_comp)
                relations.extend(mid_relations)
        
        if bom.dependencies:
            for depend in bom.dependencies:
                for dep in depend.dependsOn:
                    relations.append(
                        Relationship(
                            type="DEPENDS_ON",
                            sourceID=depend.ref.root.root,
                            targetID=dep.root.root
                        )
                    )
        
        annotations = []
        if bom.annotations:
            for anno in bom.annotations:
                subjects = []
                if anno.subjects:
                    for sub in anno.subjects:
                        if isinstance(sub, cdx_model.RefLinkType):
                            subjects.append(sub.root.root)
                        else:
                            subjects.append(sub.root)
                
                annotator = []
                if anno.organization:
                    annotator.append(self.entity_contact2individual(anno.organization))
                if anno.individual:
                    annotator.append(self.entity_contact2individual(anno.individual))
                if anno.component:
                    anno_comp, _ = self.component_cdx2mid(anno.component)
                    annotator.append(anno_comp[-1])
                if anno.service:
                    annotator.append(self.service_cdx2mid(anno.service))
                
                annotations.append(
                    Annotation(
                        type="OTHER",
                        ID=anno.bom_ref.root if anno.bom_ref else None,
                        subjects=subjects if subjects else None,
                        timestamp=anno.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if anno.timestamp else None,
                        annotator=annotator if annotator else None,
                        text=anno.text,
                        signature=self.signature_cdx2mid(anno.signature)
                    )
                )
        
        midware = Middleware(
            doc_ID=bom.serialNumber,
            bom_version=bom.version,
            doc_name="CycloneDX 1.6 Document",
            doc_namespace="https://cyclonedx.org/schema/bom/1.6",
            timestamp=timestamp,
            licenses=bom_license if bom_license else None,
            lifecycles=lfc if lfc else None,
            creator=creators if creators else None,
            components=components if components else None,
            relationship=relations if relations else None,
            properties=properties if properties else None,
            external_references=self.exRef_cdx2mid(bom.externalReferences),
            annotations=annotations if annotations else None,
            signature=self.signature_cdx2mid(bom.signature),
        )
        return midware

    def entity_contact2individual(self, entity: Optional[Union[cdx_model.OrganizationalContact, cdx_model.OrganizationalEntity]]) -> Optional[Individual]:
        if not entity:
            return None
        if isinstance(entity, cdx_model.OrganizationalContact):
            return Individual(
                type="person",
                ID=entity.bom_ref.root if entity.bom_ref else None,
                name=entity.name,
                email=entity.email,
                phone=entity.phone,
            )
        elif isinstance(entity, cdx_model.OrganizationalEntity):
            return Individual(
                type="organization",
                ID=entity.bom_ref.root if entity.bom_ref else None,
                name=entity.name,
                address=entity.address,
                url=entity.url,
                contacts=[self.entity_contact2individual(ent_contact) for ent_contact in entity.contact] if entity.contact else None
            )

    def property_cdx2mid(self, properties: Optional[List[cdx_model.Property]]) -> Optional[List[Extension]]:
        if not properties:
            return None
        exts = []
        for prop in properties:
            exts.append(
                Extension(
                    key=prop.name,
                    value=prop.value
                )
            )
        if not exts:
            exts = None
        return exts

    def hash_cdx2mid(self, hashes: Optional[List[cdx_model.Hash]]) -> Optional[List[Hash]]:
        if not hashes:
            return None
        checksum = []
        for hash_checksum in hashes:
            checksum.append(
                Hash(
                    alg=hash_checksum.alg.value,
                    value=hash_checksum.content.root
                )
            )
        if not checksum:
            checksum = None
        return checksum

    def exRef_cdx2mid(self, exRefs: Optional[List[cdx_model.ExternalReference]]) -> Optional[List[ExternalReference]]:
        if not exRefs:
            return None
        ex_refs = []
        for ref in exRefs:
            ex_refs.append(
                ExternalReference(
                    url=ref.url if isinstance(ref.url, str) else ref.url.root.root,
                    comment=ref.comment,
                    type=ref.type.value,
                    checksum=self.hash_cdx2mid(ref.hashes)
                )
            )
        if not ex_refs:
            ex_refs = None
        return ex_refs

    def signer_cdx2mid(self, signer: Optional[cdx_model.Signer]) -> Optional[Signer]:
        return Signer(
            algorithm=signer.algorithm.value if isinstance(signer.algorithm, cdx_model.Algorithm) else str(signer.algorithm),
            keyId=signer.keyId,
            publicKey=signer.publicKey.kty.value if signer.publicKey else None,
            certificatePath=signer.certificatePath,
            excludes=signer.excludes,
            value=signer.value,
        )

    def signature_cdx2mid(self, signature: Optional[cdx_model.Signature]) -> Optional[Signature]:
        if not signature:
            return None
        signature = signature.root
        if isinstance(signature, cdx_model.Signature1):
            sig = Signature(type="signers")
            if signature.signers:
                signers = []
                for signer in signature.signers:
                    signers.append(
                        self.signer_cdx2mid(signer)
                    )
                sig.sigs = signers
            return sig
        elif isinstance(signature, cdx_model.Signature2):
            sig = Signature(type="chain")
            if signature.chain:
                signers = []
                for signer in signature.chain:
                    signers.append(
                        self.signer_cdx2mid(signer)
                    )
                sig.sigs = signers
            return sig
        else:
            return Signature(
                sigs=[self.signer_cdx2mid(signature)]
            )

    def releaseNotes_cdx2mid(self, releaseNotes: Optional[cdx_model.ReleaseNotes]) -> Optional[ReleaseNotes]:
        if not releaseNotes:
            return None
        resolves = []
        if releaseNotes.resolves:
            for res in releaseNotes.resolves:
                resolves.append(
                    Issue(
                        type=res.type.value,
                        id=res.id,
                        name=res.name,
                        description=res.description,
                        source=Extension(
                            key=res.source.name if res.source.name else "name",
                            value=res.source.url
                        ) if res.source else None,
                        url_refs=res.references
                    )
                )
        
        notes = []
        if releaseNotes.notes:
            for note in releaseNotes.notes:
                notes.append(
                    Note(
                        locale=note.locale,
                        text=Text(
                            contentType=note.text.contentType,
                            content=note.text.content,
                            encoding=note.text.encoding
                        )
                    )
                )
        return ReleaseNotes(
            type=releaseNotes.type.root,
            title=releaseNotes.title,
            featuredImage=releaseNotes.featuredImage,
            socialImage=releaseNotes.socialImage,
            description=releaseNotes.description,
            timestamp=releaseNotes.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if releaseNotes.timestamp else None,
            aliases=releaseNotes.aliases,
            tags=releaseNotes.tags.root if releaseNotes.tags else None,
            resolves=resolves if resolves else None,
            notes=notes if notes else None,
            properties=self.property_cdx2mid(releaseNotes.properties),
        )

    def license_cdx2mid(self, license_choice: Optional[cdx_model.LicenseChoice]) -> Optional[List[License]]:
        if not license_choice:
            return None
        bom_license = []
        for lic in license_choice.root:
            if isinstance(lic, cdx_model.LicenseChoiceItem):
                lic = lic.license.root
                licensing = None
                if lic.licensing:
                    licensor = []
                    if lic.licensing.licensor:
                        ent_org = self.entity_contact2individual(lic.licensing.licensor.organization)
                        ent_ind = self.entity_contact2individual(lic.licensing.licensor.individual)
                        if ent_org:
                            licensor.append(ent_org)
                        if ent_ind:
                            licensor.append(ent_ind)
                    
                    licensee = []
                    if lic.licensing.licensee:
                        ent_org = self.entity_contact2individual(lic.licensing.licensee.organization)
                        ent_ind = self.entity_contact2individual(lic.licensing.licensee.individual)
                        if ent_org:
                            licensee.append(ent_org)
                        if ent_ind:
                            licensee.append(ent_ind)
                    
                    purchaser = []
                    if lic.licensing.purchaser:
                        ent_org = self.entity_contact2individual(lic.licensing.purchaser.organization)
                        ent_ind = self.entity_contact2individual(lic.licensing.purchaser.individual)
                        if ent_org:
                            purchaser.append(ent_org)
                        if ent_ind:
                            purchaser.append(ent_ind)
                    
                    licensing = Licensing(
                        altIds=lic.licensing.altIds,
                        licensor=licensor if licensor else None,
                        licensee=licensee if licensee else None,
                        purchaser=purchaser if purchaser else None,
                        purchaseOrder=lic.licensing.purchaseOrder,
                        licenseTypes=[lic_type.value for lic_type in lic.licensing.licenseTypes] if lic.licensing.licenseTypes else None,
                        lastRenewal=lic.licensing.lastRenewal.strftime("%Y-%m-%dT%H:%M:%SZ") if lic.licensing.lastRenewal else None,
                        expiration=lic.licensing.expiration.strftime("%Y-%m-%dT%H:%M:%SZ") if lic.licensing.expiration else None,
                    )
                cross_ref = []
                if lic.url:
                    cross_ref.append(
                        CrossRef(
                            url=lic.url
                        )
                    )
                lic_properties = self.property_cdx2mid(lic.properties)
                lc_name = ""
                if lic.name:
                    lc_name = lic.name
                if lic.bom_ref:
                    if not lc_name:
                        lc_name = lic.bom_ref.root
                    else:
                        lc_name += f"({lic.bom_ref.root})"
                
                bom_license.append(
                    License(
                        type=lic.acknowledgement.value if lic.acknowledgement else "concluded",
                        spdxID=lic.id.value if lic.id else None,
                        name=lc_name if lc_name else None,
                        text=Text(
                            content=lic.text.content,
                            contentType=lic.text.contentType,
                            encoding=lic.text.encoding.value if lic.text.encoding else None
                        ) if lic.text else None,
                        licensing=licensing if licensing else None,
                        crossRefs=cross_ref if cross_ref else None,
                        properties=lic_properties if lic_properties else None
                    )
                )
            elif isinstance(lic, cdx_model.LicenseChoiceItem1):
                bom_license.append(
                    License(
                        type=lic.acknowledgement.value if lic.acknowledgement else "concluded",
                        spdxID=lic.expression,
                        name=lic.bom_ref.root if lic.bom_ref else None,
                    )
                )
        if not bom_license:
            bom_license = None
        return bom_license

    def service_cdx2mid(self, serve: Optional[cdx_model.Service]) -> Optional[Service]:
        if not serve:
            return None
        return Service(
            ID=serve.bom_ref.root if serve.bom_ref else None,
            provider=self.entity_contact2individual(serve.provider),
            group=serve.group,
            name=serve.name,
            version=serve.version.root if serve.version else None,
            description=serve.description,
            endpoints=serve.endpoints,
            authenticated=serve.authenticated,
            x_trust_boundary=serve.x_trust_boundary,
            trustZone=serve.trustZone,
            data=[
                serve_data.model_dump_json(exclude_none=True) for serve_data in serve.data
            ],
            licenses=self.license_cdx2mid(serve.licenses),
            externalReferences=self.exRef_cdx2mid(serve.externalReferences),
            services=[
                self.service_cdx2mid(ser) for ser in serve.services
            ],
            releaseNotes=self.releaseNotes_cdx2mid(serve.releaseNotes),
            properties=self.property_cdx2mid(serve.properties),
            tags=serve.tags,
            signature=self.signature_cdx2mid(serve.signature),
        )

    def component_cdx2mid(self, comp: cdx_model.Component) -> Tuple[List[Component], List[Relationship]]:
        comps = []
        relations = []
        
        originator = []
        if comp.manufacturer:
            originator.append(
                self.entity_contact2individual(comp.manufacturer)
            )
        if comp.authors:
            for author in comp.authors:
                originator.append(
                    self.entity_contact2individual(author)
                )
        if comp.author:
            originator.append(
                Individual(
                    type="person",
                    name=comp.author
                )
            )
        
        swid = None
        if comp.swid:
            if comp.swid.text:
                text = Text(
                    contentType=comp.swid.text.contentType,
                    encoding=comp.swid.text.encoding,
                    content=comp.swid.text.content
                )
            swid = Swid(
                tagID=comp.swid.tagId,
                name=comp.swid.name,
                version=comp.swid.version,
                tagVersion=comp.swid.tagVersion,
                patch=comp.swid.patch,
                url=comp.swid.url,
                text=text
            )
        
        properties = []
        if comp.modified:
            properties.append(
                Extension(
                    key="modified",
                    value=str(comp.modified)
                )
            )
        
        if comp.pedigree:
            if comp.pedigree.ancestors:
                for ancestor in comp.pedigree.ancestors:
                    anc_comp, anc_relations = self.component_cdx2mid(ancestor)
                    comps.extend(anc_comp)
                    relations.extend(anc_relations)
                    relations.append(
                        Relationship(
                            type="ANCESTOR_OF",
                            sourceID=ancestor.bom_ref.root if ancestor.bom_ref else ancestor.name,
                            targetID=comp.bom_ref.root if comp.bom_ref else comp.name,
                        )
                    )

            if comp.pedigree.descendants:
                for des in comp.pedigree.descendants:
                    des_comp, des_relations = self.component_cdx2mid(des)
                    comps.extend(des_comp)
                    relations.extend(des_relations)
                    relations.append(
                        Relationship(
                            type="DESCENDANT_OF",
                            sourceID=des.bom_ref.root if des.bom_ref else des.name,
                            targetID=comp.bom_ref.root if comp.bom_ref else comp.name,
                        )
                    )
            
            if comp.pedigree.variants:
                for vari in comp.pedigree.variants:
                    vari_comp, vari_relations = self.component_cdx2mid(vari)
                    comps.extend(vari_comp)
                    relations.extend(vari_relations)
                    relations.append(
                        Relationship(
                            type="VARIANT_OF",
                            sourceID=vari.bom_ref.root if vari.bom_ref else vari.name,
                            targetID=comp.bom_ref.root if comp.bom_ref else comp.name,
                        )
                    )
        
        if comp.components:
            for compo in comp.components:
                comp_comp, comp_relations = self.component_cdx2mid(compo)
                comps.extend(comp_comp)
                relations.extend(comp_relations)
                relations.append(
                    Relationship(
                        type="CONTAINS",
                        sourceID=comp.bom_ref.root if comp.bom_ref else comp.name,
                        targetID=compo.bom_ref.root if compo.bom_ref else compo.name,
                    )
                )
        
        if comp.properties:
            comp_properties = self.property_cdx2mid(comp.properties)
            properties.extend(comp_properties)
        
        mid_comp = Component(
            type=comp.type.value,
            mime_type=comp.mime_type,
            ID=comp.bom_ref.root if comp.bom_ref else None,
            supplier=self.entity_contact2individual(comp.supplier),
            originator=originator if originator else None,
            publisher=Individual(type='organization', name=comp.publisher) if comp.publisher else None,
            group=comp.group,
            name=comp.name,
            version=comp.version.root if comp.version else None,
            description=comp.description,
            scope=comp.scope.value,
            checksum=self.hash_cdx2mid(comp.hashes),
            licenses=self.license_cdx2mid(comp.licenses),
            copyright=comp.copyright,
            cpe=comp.cpe,
            purl=comp.purl,
            omniborId=comp.omniborId,
            swhid=comp.swhid,
            swid=swid,
            external_references=self.exRef_cdx2mid(comp.externalReferences),
            releaseNotes=self.releaseNotes_cdx2mid(comp.releaseNotes),
            properties=properties if properties else None,
            tags=comp.tags,
            signature=self.signature_cdx2mid(comp.signature),
        )
        
        comps.append(mid_comp)
        return comps, relations


class Middleware2Cdx:
    def __init__(self, midware: Middleware) -> None:
        self.midware = midware
        
    def middleware2cdx(self) -> dict:
        bom = cdx_model.CyclonedxBillOfMaterialsStandard(
            bomFormat=cdx_model.BomFormat.CycloneDX,
            specVersion="1.6",
            serialNumber=self.midware.doc_ID,
            version=self.midware.bom_version,
        )
        lfc = []
        if self.midware.lifecycles:
            for lfcycle in self.midware.lifecycles:
                if lfcycle in [member.value for member in cdx_model.Phase]:
                    lfc.append(
                        cdx_model.Lifecycles(
                            phase=cdx_model.Phase(lfcycle)
                        )
                    )
                else:
                    lfc_list = lfcycle.split("; ")
                    lfc_name = lfc_list[0].strip().strip("name: ")
                    if len(lfc_list) > 1:
                        lfc_description = lfcycle.split("; ")[1].strip().strip("description: ")
                    lfc.append(
                        cdx_model.Lifecycles1(
                            name=lfc_name,
                            description=lfc_description
                        )
                    )
        
        manufacturer = None
        authors = []
        tools = None
        if self.midware.creator:
            cr_comps = []
            cr_services = []
            for cr in self.midware.creator:
                if isinstance(cr, Component):
                    cr_comps.append(
                        self.component_mid2cdx(cr)
                    )
                elif isinstance(cr, Service):
                    cr_services.append(
                        self.service_mid2cdx(cr)
                    )
                else:
                    ind = self.individual2entity_contact(cr)
                    if isinstance(ind, cdx_model.OrganizationalEntity):
                        manufacturer = ind
                    else:
                        authors.append(ind)
            if cr_comps or cr_services:
                tools = cdx_model.Tools(
                    components=cr_comps if cr_comps else None,
                    services=cr_services if cr_services else None
                )
        
        root_component = None
        supplier = None
        if self.midware.components:
            root_component = self.component_mid2cdx(self.midware.components[0])
            supplier = root_component.supplier
        
        bom.metadata = cdx_model.Metadata(
            timestamp=datetime.strptime(self.midware.timestamp, "%Y-%m-%dT%H:%M:%SZ") if self.midware.timestamp else None,
            lifecycles=lfc if lfc else None,
            tools=tools if tools else None,
            manufacturer=manufacturer if manufacturer else None,
            authors=authors if authors else None,
            component=root_component,
            supplier=supplier,
            licenses=self.license_mid2cdx(self.midware.licenses),
        )
        
        comp_dic = {}
        bom_comps = []
        if self.midware.components:
            for comp in self.midware.components:
                cdx_comp = self.component_mid2cdx(comp)
                if not cdx_comp:
                    continue
                bom_comps.append(cdx_comp)
                if cdx_comp.bom_ref:
                    comp_dic[cdx_comp.bom_ref.root] = cdx_comp
        
        depend_dic = {}
        dependencies = []
        properties = []
        if self.midware.relationship:
            for rel in self.midware.relationship:
                if rel.type == "DEPENDS_ON":
                    dep_comp = depend_dic.get(rel.sourceID, [])
                    if not dep_comp:
                        depend_dic[rel.sourceID] = dep_comp
                    dep_comp.append(rel.targetID)
                elif rel.type == "DEPENDENCY_OF":
                    dep_comp = depend_dic.get(rel.targetID, [])
                    if not dep_comp:
                        depend_dic[rel.targetID] = dep_comp
                    dep_comp.append(rel.sourceID)
                elif rel.type == "ANCESTOR_OF":
                    source_id = rel.sourceID
                    target_id = rel.targetID
                    source_comp = comp_dic.get(source_id, None)
                    target_comp = comp_dic.get(target_id, None)
                    if not (source_comp and target_comp):
                        continue
                    if not target_comp.pedigree:
                        target_comp.pedigree = cdx_model.Pedigree()
                    if not target_comp.pedigree.ancestors:
                        target_comp.pedigree.ancestors = []
                    target_comp.pedigree.ancestors.append(source_comp)
                elif rel.type == "DESCENDANT_OF":
                    source_id = rel.sourceID
                    target_id = rel.targetID
                    source_comp = comp_dic.get(source_id, None)
                    target_comp = comp_dic.get(target_id, None)
                    if not (source_comp and target_comp):
                        continue
                    if not target_comp.pedigree:
                        target_comp.pedigree = cdx_model.Pedigree()
                    if not target_comp.pedigree.descendants:
                        target_comp.pedigree.descendants = []
                    target_comp.pedigree.descendants.append(source_comp)
                elif rel.type == "VARIANT_OF":
                    source_id = rel.sourceID
                    target_id = rel.targetID
                    source_comp = comp_dic.get(source_id, None)
                    target_comp = comp_dic.get(target_id, None)
                    if not (source_comp and target_comp):
                        continue
                    if not target_comp.pedigree:
                        target_comp.pedigree = cdx_model.Pedigree()
                    if not target_comp.pedigree.variants:
                        target_comp.pedigree.variants = []
                    target_comp.pedigree.variants.append(source_comp)
                elif rel.type == "CONTAINS":
                    source_id = rel.sourceID
                    target_id = rel.targetID
                    source_comp = comp_dic.get(source_id, None)
                    target_comp = comp_dic.get(target_id, None)
                    if not (source_comp and target_comp):
                        continue
                    if not source_comp.components:
                        source_comp.components = []
                    source_comp.components.append(target_comp)
                else:
                    rel_value = f"{rel.sourceID} is {rel.type} of {rel.targetID}"
                    if rel.comment:
                        rel_value += f" ({rel.comment})"
                    properties.append(
                        cdx_model.Property(
                            name=rel.type,
                            value=rel_value
                        )
                    )
        
        for source, target in depend_dic.items():
            dependencies.append(
                cdx_model.Dependency(
                    ref=cdx_model.RefType(root=source),
                    dependsOn=[cdx_model.RefType(root=dep) for dep in target]
                )
            )
        
        annotations = []
        if self.midware.annotations:
            for anno in self.midware.annotations:
                subjects = []
                if anno.subjects:
                    pattern=r'^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+$'
                    for sub in anno.subjects:
                        if bool(re.fullmatch(pattern, sub)):
                            subjects.append(
                                cdx_model.BomLinkElementType(
                                    root=sub
                                )
                            )
                        else:
                            subjects.append(
                                cdx_model.RefLinkType(
                                    root=cdx_model.RefType(root=sub)
                                )
                            )
                
                annotator = None
                if anno.annotator:
                    for ent in anno.annotator:
                        if isinstance(ent, Individual):
                            cdx_ent = self.individual2entity_contact(ent)
                            if ent.type == "organization":
                                if not annotator:
                                    annotator = cdx_model.Annotator()
                                annotator.organization = cdx_ent
                            elif ent.type == "person":
                                if not annotator:
                                    annotator = cdx_model.Annotator1()
                                annotator.individual = cdx_ent
                        elif isinstance(ent, Component):
                            if not annotator:
                                annotator = cdx_model.Annotator2()
                            annotator.component = self.component_mid2cdx(ent)
                        elif isinstance(ent, Service):
                            if not annotator:
                                annotator = cdx_model.Annotator3()
                            annotator.service = self.service_mid2cdx(ent)
                
                annotations.append(
                    cdx_model.Annotations(
                        bom_ref=cdx_model.RefType(root=anno.ID) if anno.ID else None,
                        subjects=subjects if subjects else None,
                        annotator=annotator,
                        timestamp=datetime.strptime(anno.timestamp, "%Y-%m-%dT%H:%M:%SZ") if anno.timestamp else None,
                        text=anno.text,
                        signature=self.signature_mid2cdx(anno.signature)
                    )
                )
        
        if self.midware.license_list_version:
            properties.append(
                cdx_model.Property(
                    name="license_list_version",
                    value=self.midware.license_list_version
                )
            )
        
        if self.midware.properties:
            properties.extend(self.property_mid2cdx(self.midware.properties))
        
        bom.components = list(comp_dic.values()) if comp_dic else None
        bom.externalReferences = self.exRef_mid2cdx(self.midware.external_references)
        bom.dependencies = dependencies if dependencies else None
        bom.annotations = annotations
        bom.properties = properties
        bom.signature = self.signature_mid2cdx(self.midware.signature)
        return bom.model_dump(mode='json', by_alias=True, exclude_none=True)

    def hash_mid2cdx(self, hashes: Optional[List[Hash]]) -> Optional[List[cdx_model.Hash]]:
        if not hashes:
            return None
        checksum = []
        for hash_checksum in hashes:
            if hash_checksum.alg in [member.value for member in cdx_model.HashAlg]:
                checksum.append(
                    cdx_model.Hash(
                        alg=cdx_model.HashAlg(hash_checksum.alg),
                        content=cdx_model.HashContent(root=hash_checksum.value)
                    )
                )
        if not checksum:
            checksum = None
        return checksum

    def exRef_mid2cdx(self, exRefs: Optional[List[ExternalReference]]) -> Optional[List[cdx_model.ExternalReference]]:
        if not exRefs:
            return None
        ex_refs = []
        for ref in exRefs:
            ex_refs.append(
                cdx_model.ExternalReference(
                    url=ref.url,
                    comment=ref.comment,
                    type=cdx_model.Type3(ref.type) if ref.type in [member.value for member in cdx_model.Type3] else pydantic.AnyUrl(ref.type),
                    hashes=self.hash_mid2cdx(ref.checksum)
                )
            )
        if not ex_refs:
            ex_refs = None
        return ex_refs

    def property_mid2cdx(self, properties: Optional[List[Extension]]) -> Optional[List[cdx_model.Property]]:
        if not properties:
            return None
        exts = []
        for prop in properties:
            exts.append(
                cdx_model.Property(
                    name=prop.key,
                    value=prop.value
                )
            )
        if not exts:
            exts = None
        return exts

    def signer_mid2cdx(self, signer: Optional[Signer]) -> Optional[cdx_model.Signer]:
        return cdx_model.Signer(
            algorithm=cdx_model.Algorithm(signer.algorithm) if signer.algorithm in [member.value for member in cdx_model.Algorithm] else pydantic.AnyUrl(signer.algorithm),
            keyId=signer.keyId,
            publicKey=cdx_model.PublicKey(kty=cdx_model.KeyType(signer.publicKey)) if signer.publicKey else None,
            certificatePath=signer.certificatePath,
            excludes=signer.excludes,
            value=signer.value,
        )

    def signature_mid2cdx(self, signature: Optional[Signature]) -> Optional[cdx_model.Signature]:
        if not signature:
            return None
        cdx_signature = None
        if signature.type == "signers":
            if signature.sigs:
                signers = []
                for signer in signature.sigs:
                    signers.append(
                        self.signer_mid2cdx(signer)
                    )
                cdx_signature = cdx_model.Signature1(
                    signers=signers
                )
            return cdx_model.Signature(
                root=cdx_signature
            )
        elif signature.type == "chain":
            if signature.sigs:
                signers = []
                for signer in signature.sigs:
                    signers.append(
                        self.signer_mid2cdx(signer)
                    )
                cdx_signature = cdx_model.Signature2(
                    chain=signers
                )
            return cdx_model.Signature(
                root=cdx_signature
            )
        else:
            return cdx_model.Signature(
                root=self.signer_mid2cdx(signature.sigs[0])
            )

    def individual2entity_contact(self, ind: Optional[Individual]) -> Optional[Union[cdx_model.OrganizationalContact, cdx_model.OrganizationalEntity]]:
        if not ind:
            return None
        if ind.type == "person":
            email = None
            if ind.email:
                if ind.email.count("@") == 1:
                    email = ind.email
                    email = email.replace(",", "")
                elif ind.email.count("@") > 1:
                    for em in ind.email.split(" "):
                        if "@" in em:
                            email = em
                            break
                    email = email.replace(",", "")
            
            return cdx_model.OrganizationalContact(
                bom_ref=cdx_model.RefType(root=ind.ID) if ind.ID else None,
                name=ind.name,
                email=email,
                phone=ind.phone
            )
        elif ind.type == "organization":
            return cdx_model.OrganizationalEntity(
                bom_ref=cdx_model.RefType(root=ind.ID) if ind.ID else None,
                name=ind.name,
                address=ind.address,
                url=ind.url,
                contact=[self.individual2entity_contact(indi) for indi in ind.contacts] if ind.contacts else None
            )

    def license_mid2cdx(self, licenses: Optional[List[License]]) -> Optional[cdx_model.LicenseChoice]:
        if not licenses:
            return None
        bom_license = []
        for lic in licenses:
            if not lic.spdxID and not lic.name:
                continue
            licensing = None
            if lic.licensing:
                licensor = None
                if lic.licensing.licensor:
                    for licor in lic.licensing.licensor:
                        ent_contact = self.individual2entity_contact(licor)
                        if isinstance(ent_contact, cdx_model.OrganizationalContact):
                            if not licensor:
                                licensor = cdx_model.Licensor1(
                                    individual=ent_contact
                                )
                            else:
                                licensor.individual = ent_contact
                        else:
                            if not licensor:
                                licensor = cdx_model.Licensor(
                                    organization=ent_contact
                                )
                            else:
                                licensor.organization = ent_contact
                
                licensee = None
                for licee in lic.licensing.licensee:
                        ent_contact = self.individual2entity_contact(licee)
                        if isinstance(ent_contact, cdx_model.OrganizationalContact):
                            if not licensee:
                                licensee = cdx_model.Licensee1(
                                    individual=ent_contact
                                )
                            else:
                                licensee.individual = ent_contact
                        else:
                            if not licensee:
                                licensee = cdx_model.Licensee(
                                    organization=ent_contact
                                )
                            else:
                                licensee.organization = ent_contact

                purchaser = None
                for pur in lic.licensing.purchaser:
                        ent_contact = self.individual2entity_contact(pur)
                        if isinstance(ent_contact, cdx_model.OrganizationalContact):
                            if not purchaser:
                                purchaser = cdx_model.Purchaser1(
                                    individual=ent_contact
                                )
                            else:
                                purchaser.individual = ent_contact
                        else:
                            if not purchaser:
                                purchaser = cdx_model.Purchaser(
                                    organization=ent_contact
                                )
                            else:
                                purchaser.organization = ent_contact
            
                licensing = cdx_model.Licensing(
                    altIds=lic.licensing.altIds,
                    licensor=licensor,
                    licensee=licensee,
                    purchaser=purchaser,
                    purchaseOrder=lic.licensing.purchaseOrder,
                    licenseTypes=[cdx_model.LicenseType(lic_type) for lic_type in lic.licensing.licenseTypes],
                    lastRenewal=datetime.strptime(lic.licensing.lastRenewal, "%Y-%m-%dT%H:%M:%SZ") if lic.licensing.lastRenewal else None,
                    expiration=datetime.strptime(lic.licensing.expiration, "%Y-%m-%dT%H:%M:%SZ") if lic.licensing.expiration else None,
                )
            
            url = None
            if lic.crossRefs:
                for ref in lic.crossRefs:
                    if ref.url:
                        url = ref.url
            
            lic_name = None
            lic_ref = None
            if lic.name:
                lic_name_ls = lic.name.split("(")
                lic_name = lic_name_ls[0].strip()
                if len(lic_name_ls) > 1:
                    lic_ref = lic_name_ls[1].strip().strip(")")
                    if lic_ref:
                        lic_ref = cdx_model.RefType(root=lic_ref)
                    else:
                        lic_ref = None
            
            lic_properties = []
            if lic.crossRefs:
                for ref in lic.crossRefs:
                    value = ""
                    if ref.isLive:
                        value += "isLive; "
                    if ref.isValid:
                        value += "isValid; "
                    if ref.isWayBackLink:
                        value += "isWayBackLink; "
                    if ref.match:
                        value += f"match: {ref.match}; "
                    if ref.order:
                        value += f"order: {str(ref.order)}; "
                    if ref.timestamp:
                        value += f"timestamp: {ref.timestamp}; "
                    if value:
                        lic_properties.append(
                            cdx_model.Property(
                                name=ref.url,
                                value=value
                            )
                        )
            
            if lic.properties:
                lic_properties.extend(self.property_mid2cdx(lic.properties))
            
            text = None
            if lic.text:
                text = cdx_model.Attachment(
                    content=lic.text.content,
                    contentType=lic.text.contentType,
                    encoding=cdx_model.Encoding(lic.text.encoding) if lic.text.encoding else None
                )
            
            # License1
            if lic.spdxID in [member.value for member in cdx_model.spdx.Schema]:
                root_license = cdx_model.License1(
                    id=cdx_model.spdx.Schema(lic.spdxID),
                    name=lic_name,
                    bom_ref=lic_ref,
                    acknowledgement=cdx_model.LicenseAcknowledgementEnumeration(lic.type) if lic.type in [member.value for member in cdx_model.LicenseAcknowledgementEnumeration] else None,
                    text=text,
                    url=url,
                    licensing=licensing,
                    properties=lic_properties if lic_properties else None
                )
                bom_license.append(
                    cdx_model.LicenseChoiceItem(
                        license=cdx_model.License(
                            root=root_license
                        )
                    )
                )
            elif lic.spdxID:
                bom_license.append(
                    cdx_model.LicenseChoiceItem1(
                        expression=lic.spdxID,
                        acknowledgement=cdx_model.LicenseAcknowledgementEnumeration(lic.type) if lic.type in [member.value for member in cdx_model.LicenseAcknowledgementEnumeration] else None,
                        bom_ref=cdx_model.RefType(root=lic.name) if lic.name else None
                    )
                )
            # License2
            else:
                root_license = cdx_model.License2(
                    name=lic_name,
                    bom_ref=lic_ref,
                    acknowledgement=cdx_model.LicenseAcknowledgementEnumeration(lic.type) if lic.type in [member.value for member in cdx_model.LicenseAcknowledgementEnumeration] else None,
                    text=text,
                    url=url,
                    licensing=licensing,
                    properties=lic_properties  if lic_properties else None
                )
                bom_license.append(
                    cdx_model.LicenseChoiceItem(
                        license=cdx_model.License(
                            root=root_license
                        )
                    )
                )
        return cdx_model.LicenseChoice(root=bom_license)

    def releaseNotes_mid2cdx(self, releaseNotes: Optional[ReleaseNotes]) -> Optional[cdx_model.ReleaseNotes]:
        if not releaseNotes:
            return None
        resolves = []
        if releaseNotes.resolves:
            for res in releaseNotes.resolves:
                resolves.append(
                    cdx_model.Issue(
                        type=cdx_model.Type2(res.type),
                        id=res.id,
                        name=res.name,
                        description=res.description,
                        source=cdx_model.Source(
                            name=res.source.key,
                            url=res.source.value
                        ) if res.source else None,
                        references=res.url_refs
                    )
                )
        
        notes = []
        if releaseNotes.notes:
            for note in releaseNotes.notes:
                notes.append(
                    cdx_model.Note(
                        locale=cdx_model.LocaleType(root=note.locale) if note.locale in [member.value for member in cdx_model.LocaleType] else None,
                        text=cdx_model.Attachment(
                            content=note.text.content,
                            contentType=note.text.contentType,
                            encoding=cdx_model.Encoding(note.text.encoding) if note.text.encoding else None
                        )
                    )
                )
        return cdx_model.ReleaseNotes(
            type=cdx_model.ReleaseType(root=releaseNotes.type),
            title=releaseNotes.title,
            featuredImage=releaseNotes.featuredImage,
            socialImage=releaseNotes.socialImage,
            description=releaseNotes.description,
            timestamp=datetime.strptime(releaseNotes.timestamp, "%Y-%m-%dT%H:%M:%SZ") if releaseNotes.timestamp else None,
            aliases=releaseNotes.aliases,
            tags=cdx_model.Tags(root=releaseNotes.tags) if releaseNotes.tags else None,
            resolves=resolves if resolves else None,
            notes=notes if notes else None,
            properties=self.property_mid2cdx(releaseNotes.properties),
        )

    def component_mid2cdx(self, comp: Component) -> cdx_model.Component:
        if comp.type == "Snippet":
            return None
        bom_type = cdx_model.Type.library
        type_str = comp.type.lower().replace("_", "-").split(":")[-1]
        for type_enum in [member.value for member in cdx_model.Type]:
            if type_enum in type_str:
                bom_type = cdx_model.Type(type_enum)
                break
        
        manufacturer = None
        authors = []
        if comp.originator:
            for entity in comp.originator:
                ent = self.individual2entity_contact(entity)
                if isinstance(ent, cdx_model.OrganizationalContact):
                    authors.append(ent)
                else:
                    manufacturer = ent
        
        modified = None
        modified_property = self.match_property("modified", comp.properties)
        if modified_property:
            for prop in modified_property:
                if prop == "True":
                    modified = True
                elif prop == "False":
                    modified = False
        
        swid = None
        if comp.swid:
            if comp.swid.text:
                text = cdx_model.Attachment(
                    contentType=comp.swid.text.contentType,
                    encoding=cdx_model.Encoding(comp.swid.text.encoding),
                    content=comp.swid.text.content
                )
            swid = cdx_model.Swid(
                tagId=comp.swid.tagID,
                name=comp.swid.name,
                version=comp.swid.version,
                tagVersion=comp.swid.tagVersion,
                patch=comp.swid.patch,
                text=text,
                url=comp.swid.url
            )
        
        comp_properties = []
        comp_properties.append(
            cdx_model.Property(
                name="type",
                value=comp.type
            )
        )
        props = self.property_mid2cdx(comp.properties)
        if props:
            comp_properties.extend(props)
        
        if comp.verificationCodeExcludedFiles:
            comp_properties.append(
                cdx_model.Property(
                    name="verificationCodeExcludedFiles",
                    value=", ".join(comp.verificationCodeExcludedFiles)
                )
            )
        
        if comp.verificationCodeValue:
            comp_properties.append(
                cdx_model.Property(
                    name="verificationCodeValue",
                    value=comp.verificationCodeValue
                )
            )
        
        if comp.download_location:
            comp_properties.append(
                cdx_model.Property(
                    name="download_location",
                    value=comp.download_location
                )
            )
        
        if comp.source_repo:
            comp_properties.append(
                cdx_model.Property(
                    name="source_repo",
                    value=comp.source_repo
                )
            )
        
        if comp.homepage:
            comp_properties.append(
                cdx_model.Property(
                    name="homepage",
                    value=comp.homepage
                )
            )
        
        if comp.source_info:
            comp_properties.append(
                cdx_model.Property(
                    name="source_info",
                    value=comp.source_info
                )
            )
        
        if comp.built_date:
            comp_properties.append(
                cdx_model.Property(
                    name="built_date",
                    value=comp.built_date
                )
            )
        
        if comp.release_date:
            comp_properties.append(
                cdx_model.Property(
                    name="release_date",
                    value=comp.release_date
                )
            )
        
        if comp.valid_until_date:
            comp_properties.append(
                cdx_model.Property(
                    name="valid_until_date",
                    value=comp.valid_until_date
                )
            )
        
        return cdx_model.Component(
            type=bom_type,
            mime_type=comp.mime_type,
            bom_ref=cdx_model.RefType(root=comp.ID) if comp.ID else None,
            supplier=self.individual2entity_contact(comp.supplier),
            manufacturer=manufacturer if manufacturer else None,
            authors=authors if authors else None,
            publisher=comp.publisher.name if comp.publisher else None,
            group=comp.group,
            name=comp.name,
            version=cdx_model.Version(root=comp.version) if comp.version else None,
            description=comp.description,
            scope=cdx_model.Scope(comp.scope) if comp.scope in [member.value for member in cdx_model.Scope] else None,
            hashes=self.hash_mid2cdx(comp.checksum),
            licenses=self.license_mid2cdx(comp.licenses),
            copyright=comp.copyright,
            cpe=comp.cpe,
            purl=comp.purl,
            omniborId=comp.omniborId,
            swhid=comp.swhid,
            swid=swid,
            modified=modified,
            # pedigree=,
            externalReferences=self.exRef_mid2cdx(comp.external_references),
            # components=,
            releaseNotes=self.releaseNotes_mid2cdx(comp.releaseNotes),
            properties=comp_properties,
            tags=comp.tags,
            signature=self.signature_mid2cdx(comp.signature),
        )

    def match_property(self, key: str, extensions: Optional[List[Extension]]) -> Optional[List[str]]:
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

    def service_mid2cdx(self, serve: Optional[Service]) -> Optional[cdx_model.Service]:
        if not serve:
            return None
        return cdx_model.Service(
            bom_ref=cdx_model.RefType(root=serve.ID) if serve.ID else None,
            provider=self.individual2entity_contact(serve.provider),
            group=serve.group,
            name=serve.name,
            version=cdx_model.Version(root=serve.version) if serve.version else None,
            description=serve.description,
            endpoints=serve.endpoints,
            authenticated=serve.authenticated,
            x_trust_boundary=serve.x_trust_boundary,
            trustZone=serve.trustZone,
            data=[cdx_model.ServiceData(**json.loads(sev_data)) for sev_data in serve.data],
            licenses=self.license_mid2cdx(serve.licenses),
            externalReferences=self.exRef_mid2cdx(serve.externalReferences),
            services=[
                self.service_mid2cdx(ser) for ser in serve.services
            ],
            releaseNotes=self.releaseNotes_mid2cdx(serve.releaseNotes),
            properties=self.property_mid2cdx(serve.properties),
            tags=serve.tags,
            signature=self.signature_mid2cdx(serve.signature),
        )

if __name__ == '__main__':
    examples = [
        "/home/jcg/SBOM/sbom-example/scancode-sbom/syft-cdx.json",
        "/home/jcg/SBOM/sbom-example/scancode-sbom/syft-spdx-cdx.json",
        "/home/jcg/SBOM/sbom-example/scancode-sbom/cve-bin-tool-cdx.json",
        "/home/jcg/SBOM/sbom-example/scancode-sbom/cdxgen.json",
        # "/home/jcg/SBOM/sbom-example/scancode-sbom/cdx-py-cdx-env.json"
    ]
    for path in examples:
        print(path)
        bom = json.load(open(path, "r"))
        midware = Cdx2Middleware(bom).cdx2middleware()
        midware_json = midware.model_dump(by_alias=True, exclude_none=True)
        json.dump(midware_json, open("/home/jcg/SBOM/sbom-generator/SbomGT/output/midware.json", "w"), indent=4)
        midware = json.load(open("/home/jcg/SBOM/sbom-generator/SbomGT/output/midware.json", "r"))
        Middleware2Cdx(Middleware(**midware)).middleware2cdx()
        