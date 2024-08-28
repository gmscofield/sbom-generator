from typing import List
import json
import warnings
from uuid import uuid4
from datetime import datetime
from packageurl import PackageURL
from ...output import middleware
from ..util.utils import Util


class Merge_SBOM:
    def __init__(self, input: List[str], output: str, model: str) -> None:
        self.input = input
        self.output = output
        self.model = model
    
    def merge_midware(self, root_midware: middleware.Middleware, sub_midware: middleware.Middleware) -> middleware.Middleware:
        root_midware.doc_name = f"{root_midware.doc_name}(merged with {sub_midware.doc_name})"
        if root_midware.bom_version:
            root_midware.bom_version += 1
        root_midware.doc_ID = f"urn:uuid:{uuid4()}"
        root_midware.timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        purl = PackageURL(type = "github", namespace = "https://github.com/gmscofield/", name = "sbom-generator", version = "1.0").to_string()
        creators = root_midware.creator if root_midware.creator else []
        if not "SbomGT" in [creator.name for creator in creators]:
            creators.append(
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
        root_midware.creator = creators
        
        if sub_midware.properties:
            properties = root_midware.properties if root_midware.properties else []
            for prop in sub_midware.properties:
                properties.append(
                    middleware.Extension(
                        key=f"{sub_midware.doc_name}({sub_midware.doc_ID})-{prop.key}",
                        value=prop.value,
                    )
                )
            root_midware.properties = properties
        
        if sub_midware.external_references:
            external_references = root_midware.external_references if root_midware.external_references else []
            for ref in sub_midware.external_references:
                ref.comment = f"{sub_midware.doc_name}({sub_midware.doc_ID})-{ref.comment}"
                external_references.append(ref)
            root_midware.external_references = external_references

        if sub_midware.annotations:
            annotations = root_midware.annotations if root_midware.annotations else []
            for anno in sub_midware.annotations:
                anno.text = f"{sub_midware.doc_name}({sub_midware.doc_ID})-{anno.text}"
                annotations.append(anno)
            root_midware.annotations = annotations
        
        root_comps = {}
        if root_midware.components:
            for comp in root_midware.components:
                root_comps[comp.ID] = comp
        
        sub_comps = {}
        sub_compID_list = []
        if sub_midware.components:
            for comp in sub_midware.components:
                sub_comps[comp.ID] = comp
                sub_compID_list.append(comp.ID)
        
        root_root, root_dep = Util.construct_dep_tree(root_midware.relationship)
        sub_root, sub_dep = Util.construct_dep_tree(sub_midware.relationship)

        # 在root中的relationship，移除所有与sub树节点有关的依赖关系，删除只存在于sub树中的节点，
        # 对于与其他节点之间存在依赖关系的节点，只删除依赖关系，不删除节点；
        # 根据sub树，在root树中替换所有重复的节点，添加sub树中引入的新节点，重新构建所有依赖关系
                
        components = root_midware.components if root_midware.components else []
        relations = root_midware.relationship if root_midware.relationship else []
        
        # 构建sub树中所有节点到root树中节点的映射
        sub2root_comp = []
        for comp in sub_midware.components:
            flag = False
            for root_comp in root_midware.components:
                if comp.ID == root_comp.ID or comp.name == root_comp.name:
                    if comp.version != root_comp.version:
                        warnings.warn(f"Component {comp.name} has different versions in two SBOMs", UserWarning)
                    sub2root_comp.append(root_comp.ID)
                    flag = True
                    break
            if not flag:
                sub2root_comp.append(None)
        
        # 从root树中删除所有sub子树相关的依赖关系
        # sub_tree_nodes记录root树中所有以sub树根节点为树根的子树中所包含的节点
        sub_tree_nodes = set()
        for sub_root_node in sub_root:
            comp_node = sub2root_comp[sub_compID_list.index(sub_root_node)]
            if not comp_node:
                continue
            que = [(comp_node, root_dep.get(comp_node, []))]
            while que:
                cur = que.pop(0)
                sub_tree_nodes.add(cur[0])
                for node in cur[1]:
                    sub_tree_nodes.add(node)
                for rel in relations:
                    if rel.type == "DEPENDS_ON":
                        if rel.sourceID == cur[0] and rel.targetID in cur[1]:
                            relations.remove(rel)
                    elif rel.type == "DEPENDENCY_OF":
                        if rel.targetID == cur[0] and rel.sourceID in cur[1]:
                            relations.remove(rel)
                que.extend([(comp, root_dep.get(comp, [])) for comp in cur[1]])
        
        # 删除只存在于旧sub树中的节点
        # 为什么要分1、2、0？
        # 0表示孤悬节点，可以直接删除；1表示只在依赖树中出现过；2表示在其他关系中出现过，不可以随便删除
        sub_tree_nodes = list(sub_tree_nodes)
        vis_sub_tree_nodes = [0 for _ in range(len(sub_tree_nodes))]
        for node in sub_tree_nodes:
            for rel in relations:
                if rel.type == "DEPENDS_ON":
                    if rel.targetID == node:
                        if vis_sub_tree_nodes[sub_tree_nodes.index(node)] == 0:
                            vis_sub_tree_nodes[sub_tree_nodes.index(node)] = 1
                elif rel.type == "DEPENDENCY_OF":
                    if rel.sourceID == node:
                        if vis_sub_tree_nodes[sub_tree_nodes.index(node)] == 0:
                            vis_sub_tree_nodes[sub_tree_nodes.index(node)] = 1
                elif rel.sourceID == node or rel.targetID == node:
                    vis_sub_tree_nodes[sub_tree_nodes.index(node)] = 2
        
        remove_nodes = []
        for i, node in enumerate(sub_tree_nodes):
            if node in sub2root_comp:
                sub_node = sub_comps[sub_compID_list[sub2root_comp.index(node)]]
                if node == sub_node.ID:
                    components.remove(root_comps[node])
                    remove_nodes.append(node)
                    continue
            if vis_sub_tree_nodes[i] == 0:
                components.remove(root_comps[node])
                remove_nodes.append(node)
            elif vis_sub_tree_nodes[i] == 1:
                if node in sub2root_comp:
                    components.remove(root_comps[node])
                    remove_nodes.append(node)
            elif vis_sub_tree_nodes[i] == 2:
                if node in sub2root_comp:
                    if root_comps[node].ID == sub_node.ID and root_comps[node].name == sub_node.name and root_comps[node].version == sub_node.version:
                        components.remove(root_comps[node])
                        remove_nodes.append(node)
        
        # 不一定bom里面所有的节点都在树里面
        # 将sub树中的节点加入到root树中
        for i, comp_id in enumerate(sub2root_comp):
            if not comp_id:
                continue
            sub_comp_id = sub_compID_list[i]
            components.append(sub_comps[sub_comp_id])
        
        # 重新构建依赖关系
        for rel in relations:
            for node in remove_nodes:
                if rel.sourceID == node:
                    rel.sourceID = sub_compID_list[sub2root_comp.index(node)]
                if rel.targetID == node:
                    rel.targetID = sub_compID_list[sub2root_comp.index(node)]
        
        for rel in sub_midware.relationship:
            flag = False
            for root_rel in relations:
                if rel.type == root_rel.type and rel.sourceID == root_rel.sourceID and rel.targetID == root_rel.targetID:
                    flag = True
                    break
            if not flag:
                relations.append(rel)
        
        root_midware.components = components
        root_midware.relationship = relations
        return root_midware
    
    def merge_sbom(self) -> None:
        boms = []
        for bom_path in self.input:
            try:
                boms.append(json.load(open(bom_path, "r")))
            except:
                raise Exception("Only JSON format is supported for merging SBOMs")
        
        root_midware = Util.choose_model(boms[0])
        sub_midware = Util.choose_model(boms[1])
        merged_midware = self.merge_midware(root_midware, sub_midware)
        Util.make_output(merged_midware, self.model, self.output)
