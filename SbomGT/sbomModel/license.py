from .universal import Ref, IDManager


class License:
    def __init__(self, licenseID = IDManager.get_licenseID(), 
                 licenseName = None, 
                 licenseText = None, 
                 checksum = None, 
                 licenseRef = Ref()):
        self.licenseID = licenseID
        self.licenseName = licenseName
        self.licenseText = licenseText
        self.licenseChecksum = checksum
        self.licenseRef = licenseRef

    def license2Dict(self):
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
    def __init__(self):
        self.licenseList = []
        self.cnt = 0

    def insert(self, license):
        self.licenseList.append(license)
        self.cnt += 1
        
    def is_existLicense(self, license):
        for lc in self.licenseList:
            if lc.licenseID == license.licenseID or lc.licenseName == license.licenseName:
                return lc
        return None

    def licenseList2Dict(self):
        otherLicenseList = []
        for license in self.licenseList:
            otherLicenseList.append(license.license2Dict())
        return otherLicenseList
