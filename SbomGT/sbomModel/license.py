from typing import Optional, List
from .util import Ref


class License:
    def __init__(
        self, 
        licenseID: Optional[str] = None, 
        licenseName: Optional[str] = None, 
        licenseText: Optional[str] = None, 
        checksum: Optional[List] = None, 
        licenseRef: Optional[Ref] = Ref()
    ) -> None:
        self.licenseID = licenseID
        self.licenseName = licenseName
        self.licenseText = licenseText
        self.licenseChecksum = checksum
        self.licenseRef = licenseRef

    def license2Dict(self) -> dict:
        licenseDict = {
            "LicenseID": self.licenseID,
            "LicenseName": self.licenseName,
            "LicenseText": self.licenseText
        }
        if self.licenseChecksum:
            licenseDict["LicenseChecksum"] = self.licenseChecksum
        if self.licenseRef.cnt > 0:
            licenseDict["LicenseRef"] = self.licenseRef.docRef
        return licenseDict
        

class LicenseList:
    def __init__(self) -> None:
        self.licenseList = []
        self.cnt = 0

    def insert(self, license: License) -> None:
        self.licenseList.append(license)
        self.cnt += 1
        
    def is_existLicense(self, license: License) -> Optional[License]:
        for lc in self.licenseList:
            if lc.licenseID == license.licenseID or lc.licenseName == license.licenseName:
                return lc
        return None

    def licenseList2Dict(self) -> List:
        otherLicenseList = []
        for license in self.licenseList:
            otherLicenseList.append(license.license2Dict())
        return otherLicenseList
