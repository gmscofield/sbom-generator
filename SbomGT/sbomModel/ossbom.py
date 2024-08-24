import json
import sys
from typing import List, Dict
import yaml
import hashlib
from .documentInfo import DocumentInfo
from .pkgInfo import PkgList
from .innerInfo import InnerList
from .validityInfo import ValidityInfo
from .license import LicenseList
from .relationInfo import RelationshipInfo
from .annotation import Annotation



class OSSBOM():
    def __init__(
        self, 
        docInfo: DocumentInfo = DocumentInfo(), 
        pkgList: PkgList = PkgList(),
        innerList: InnerList = InnerList(),
        validityInfo: ValidityInfo = ValidityInfo(),
        relashionshipInfo: RelationshipInfo = RelationshipInfo(),
        licenseList: LicenseList = LicenseList(), 
        annotation: Annotation = Annotation()
    ) -> None:
        self.docInfo = docInfo
        self.pkgList = pkgList
        self.innerList = innerList
        self.validityInfo = validityInfo
        self.relashionshipInfo = relashionshipInfo
        self.licenseList = licenseList
        self.annotation = annotation

    
    def toDict(self) -> dict:
        bomDict = dict()
        bomDict.update({"DocumentInformation": self.docInfo.toDict()})
        bomDict.update({"PackageInformation": self.pkgList.toDict()})
        bomDict.update({"InnerInformation": self.innerList.toDict()})
        bomDict.update({"ValidityInformation": self.validityInfo.toDict()})
        bomDict.update({"RelationshipInformation": self.relashionshipInfo.toDict()})
        if self.licenseList.cnt > 0:
            bomDict.update({"OtherLicensingInformation": self.licenseList.licenseList2Dict()})
        if self.annotation.cnt > 0:
            bomDict.update({"Annotation": self.annotation.toDict()})
        return bomDict

    @staticmethod
    def Dfs(dict: Dict, layer: int) -> str:
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

    def toTXT(self, IOwriter: sys.TextIO = sys.stdout) -> None:
        content = OSSBOM.Dfs(self.toDict(), 0)
        IOwriter.write(content)

    def toJSON(self, IOwriter: sys.TextIO = sys.stdout) -> None:
        json.dump(self.toDict(), IOwriter, indent=4, default=str)
    
    def toYAML(self, IOwriter: sys.TextIO = sys.stdout) -> None:
        yaml.dump(self.toDict(), IOwriter, sort_keys=False)
    
    def toHash(self, path: str) -> None:
        algo = hashlib.sha256()
        with open(path, "rb") as f:
            algo.update(f.read())
        fwriter = open(path + ".sha256", "w")
        sbom_hash = algo.hexdigest()
        fwriter.write(sbom_hash)
        fwriter.close()
