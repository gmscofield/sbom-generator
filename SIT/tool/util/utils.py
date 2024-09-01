from typing import List, Optional, Tuple
import json
from ...output import middleware, cdx_conversion, spdx_conversion, ossbom_conversion


class Util:
    SOURCE2TARGET = ['DESCRIBES', 'CONTAINS', 'DEPENDS_ON', 'EXAMPLE_OF', 'GENERATED_FROM', 'DISTRIBUTION_ARTIFACT', 
        'PATCH_FOR', 'PATCH_APPLIED', 'COPY_OF', 'FILE_ADDED', 'FILE_DELETED', 'FILE_MODIFIED', 'EXPANDED_FROM_ARCHIVE', 
        'DYNAMIC_LINK', 'STATIC_LINK', 'DOCUMENTATION_OF', 'OPTIONAL_COMPONENT_OF', 'METAFILE_OF', 'PACKAGE_OF', 'AMENDS', 
        'PREREQUISITE_FOR', 'REQUIREMENT_DESCRIPTION_FOR', 'SPECIFICATION_FOR', 'OTHER']
    TARGET2SOURCE = ['DESCRIBED_BY', 'CONTAINED_BY', 'DEPENDENCY_OF', 'DEPENDENCY_MANIFEST_OF', 'BUILD_DEPENDENCY_OF', 
        'DEV_DEPENDENCY_OF', 'OPTIONAL_DEPENDENCY_OF', 'PROVIDED_DEPENDENCY_OF', 'RUNTIME_DEPENDENCY_OF', 'GENERATES', 
        'ANCESTOR_OF', 'DESCENDANT_OF', 'VARIANT_OF', 'DATA_FILE_OF', 'TEST_CASE_OF', 'BUILD_TOOL_OF', 'DEV_TOOL_OF', 
        'TEST_OF', 'TEST_TOOL_OF', 'HAS_PREREQUISITE', 'OTHER']
    
    @staticmethod
    def construct_dep_tree(relations: Optional[List[middleware.Relationship]]) -> Tuple[List[str], dict]:
        if not relations:
            return None, {}
        leaf_node_comp = {}
        dep_tree = {}
        for rel in relations:
            if rel.type == "DEPENDS_ON":
                leaf_node_comp[rel.targetID] = True
                if leaf_node_comp.get(rel.sourceID) == None:
                    leaf_node_comp[rel.sourceID] = False
                source_dep = dep_tree.get(rel.sourceID, [])
                source_dep.append(rel.targetID)
                dep_tree[rel.sourceID] = source_dep
            elif rel.type == "DEPENDENCY_OF":
                leaf_node_comp[rel.sourceID] = True
                if leaf_node_comp.get(rel.targetID) == None:
                    leaf_node_comp[rel.targetID] = False
                target_dep = dep_tree.get(rel.targetID, [])
                target_dep.append(rel.sourceID)
                dep_tree[rel.targetID] = target_dep
                        
        root_comp = []
        for comp, is_leaf in leaf_node_comp.items():
            if not is_leaf:
                root_comp.append(comp)
        
        return root_comp, dep_tree

    @staticmethod
    def choose_model(bom_dic: dict) -> middleware.Middleware:
        if bom_dic.get("bomFormat", None) == "CycloneDX":
            return cdx_conversion.Cdx2Middleware(bom_dic).cdx2middleware()
        elif bom_dic.get("spdxVersion", None) == "SPDX-2.3":
            return spdx_conversion.Spdx2Middleware(bom_dic).spdx2middleware()
        elif bom_dic.get("DocumentInformation", {}).get("DocumentFormat", None) == "OSSBOM":
            return ossbom_conversion.Ossbom2Middleware(bom_dic).ossbom2middleware()
        elif bom_dic.get("type", None) == "Middleware":
            return middleware.Middleware(**bom_dic)
        else:
            raise Exception("Unsupported SBOM format")
    
    @staticmethod
    def convert2model(midware: middleware.Middleware, model: str) -> dict:
        if model == "cyclonedx":
            return cdx_conversion.Middleware2Cdx(midware).middleware2cdx()
        elif model == "spdx":
            return spdx_conversion.Middleware2Spdx(midware).middleware2spdx()
        elif model == "ossbom":
            return ossbom_conversion.Middleware2Ossbom(midware).middleware2ossbom()
        elif model == "middleware":
            return midware.model_dump(mode='json', exclude_none=True)
    
    @staticmethod
    def make_output(midware: middleware.Middleware, model: str, output: str) -> None:
        out_bom = Util.convert2model(midware, model)
        
        if output == "-":
            print(json.dumps(out_bom, indent=4))
        else:
            json.dump(out_bom, open(output, "w"), indent=4)
