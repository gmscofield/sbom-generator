import json
import sys
from typing import List, Dict
import yaml
import hashlib
from .documentInfo import DocumentInfo
from .pkgInfo import PkgList
from .componentInfo import ComponentList
from .validityInfo import ValidityInfo
from .license import LicenseList
from .relationInfo import RelationshipInfo
from .annotation import Annotation



class OSSBOM():
    def __init__(self, level = 1, 
                    docInfo = DocumentInfo(), 
                    pkgList = PkgList(),
                    componentList = ComponentList(),
                    validityInfo = ValidityInfo(),
                    relashionshipInfo = RelationshipInfo(),
                    licenseList = LicenseList(), 
                    annotation = Annotation()):
        self.level = level
        self.docInfo = docInfo
        self.pkgList = pkgList
        self.componentList = componentList
        self.validityInfo = validityInfo
        self.relashionshipInfo = relashionshipInfo
        self.licenseList = licenseList
        self.annotation = annotation

    
    def toDict(self):
        bomDict = dict()
        bomDict.update({"DocumentInformation": self.docInfo.toDict()})
        bomDict.update({"PackageInformation": self.pkgList.toDict()})
        if self.level >= 2 and self.componentList.cnt > 0:
            bomDict.update({"ComponentInformation": self.componentList.toDict()})
        bomDict.update({"ValidityInformation": self.validityInfo.toDict(self.level)})
        bomDict.update({"RelationshipInformation": self.relashionshipInfo.toDict()})
        if self.licenseList.cnt > 0:
            bomDict.update({"OtherLicensingInformation": self.licenseList.licenseList2Dict()})
        if self.annotation.cnt > 0:
            bomDict.update({"Annotation": self.annotation.toDict()})
        return bomDict

    @staticmethod
    def Dfs(dict, layer):
        ans = ""
        for key, value in dict.items():
            if layer == 0:
                if  key != "DocumentInformation":
                    ans += "\n"
                ans += "## "
            if isinstance(value, Dict):
                ans += f"{key}:\n"
                ans += OSSBOM.Dfs(value, layer + 1)
            elif isinstance(value, List):
                if "Ref" in key:
                    for ref in value:
                        ans += f"{key}: {ref['Name']} {ref['DocumentURI']}\n"
                        
                else:
                    ans += f"{key}:\n"
                    for item in value:
                        ans += OSSBOM.Dfs(item, layer + 1)
            else:
                ans += f"{key}: {value}\n"
        return ans

    def toTXT(self, IOwriter = sys.stdout):
        content = OSSBOM.Dfs(self.toDict(), 0)
        IOwriter.write(content)

    def toJSON(self, IOwriter = sys.stdout):
        json.dump(self.toDict(), IOwriter, indent=4, default=str)
    
    def toYAML(self, IOwriter = sys.stdout):
        yaml.dump(self.toDict(), IOwriter, sort_keys=False)
    
    def toHash(self, path):
        algo = hashlib.sha256()
        with open(path, "rb") as f:
            algo.update(f.read())
        fwriter = open(path + ".sha256", "w")
        sbom_hash = algo.hexdigest()
        fwriter.write(sbom_hash)
        fwriter.close()
