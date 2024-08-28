from typing import List
import json
from uuid import uuid4
from datetime import datetime
from packageurl import PackageURL
from ...output import middleware
from ..util.utils import Util


class Export_SBOM:
    def __init__(self, input: str, output: str, model: str, id: List[str]) -> None:
        self.input = input
        self.output = output
        self.model = model
        self.id = id
    
    def export_sbom(self) -> None:
        try:
            bom = json.load(open(self.input, "r"))
        except:
            raise Exception("Only JSON format is supported for exporting SBOMs")
        
        midware = Util.choose_model(bom)
        comp_ls = [comp.ID for comp in midware.components]
        for comp_id in self.id:
            if not comp_id in comp_ls:
                raise Exception(f"Component {comp_id} not found in SBOM")
        
        root_comp, dep_tree = Util.construct_dep_tree(midware.relationship)
        exported_comps = set()
        exported_rels = []
        comp_que = self.id
        while comp_que:
            cur = comp_que.pop(0)
            exported_comps.add(cur)
            deps = dep_tree.get(cur, [])
            comp_que.extend(deps)
            exported_comps.update(deps)
        
        for rel in midware.relationship:
            if rel.type == "DEPENDS_ON" or rel.type == "DEPENDENCY_OF":
                if rel.sourceID in exported_comps and rel.targetID in exported_comps:
                    exported_rels.append(rel)
            else:
                if rel.type in Util.SOURCE2TARGET:
                    if rel.sourceID in exported_comps:
                        exported_comps.add(rel.targetID)
                        exported_rels.append(rel)
                elif rel.type in Util.TARGET2SOURCE:
                    if rel.targetID in exported_comps:
                        exported_comps.add(rel.sourceID)
                        exported_rels.append(rel)
        
        midware.components = [comp for comp in midware.components if comp.ID in exported_comps]
        midware.relationship = exported_rels
        
        midware.doc_ID = f"urn:uuid:{uuid4()}"
        midware.doc_name = f"{midware.doc_name}(exported)"
        midware.timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        purl = PackageURL(type = "github", namespace = "https://github.com/gmscofield/", name = "sbom-generator", version = "1.0").to_string()
        creator = midware.creator if midware.creator else []
        if not "SbomGT" in [cr.name for cr in creator]:
            creator.append(
                middleware.Component(
                    type="Package: LIBRARY",
                    name="SbomGT",
                    version="1.0",
                    ID=purl,
                    purl=purl,
                    originator=[middleware.Individual(type='person', name='gmscofield')],
                    licenses=[middleware.License(type='declared', spdxID='MIT')],
                    download_location='https://github.com/gmscofield/sbom-generator',
                    source_repo='https://github.com/gmscofield/sbom-generator',
                    homepage='https://github.com/gmscofield',
                )
            )
        midware.creator = creator
        
        Util.make_output(midware, self.model, self.output)