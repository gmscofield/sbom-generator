from datetime import datetime
from . import LicenseListVersion


class ResourceValidityInfo:
    def __init__(self, resourceID, 
                    supplier = None,
                    originator = None,
                    downloadLocation = None,
                    sourceRepo = None,
                    homepage = None,
                    releaseTime = None,
                    builtTime = None,
                    validUntilTime = None):
        self.resourceID = resourceID
        self.supplier = supplier if supplier else None
        self.originator = originator if originator else None
        self.downloadLocation = downloadLocation if downloadLocation else None
        self.sourceRepo = sourceRepo if sourceRepo else None
        self.homepage = homepage if homepage else None
        self.releaseTime = releaseTime if releaseTime else None
        self.builtTime = builtTime if builtTime else None
        self.validUntilTime = validUntilTime if validUntilTime else None

    def toDict(self):
        rsInfo = {
            "ResourceID": self.resourceID
        }
        if self.supplier:
            rsInfo["Supplier"] = self.supplier
        if self.originator:
            rsInfo["Originator"] = self.originator
        if self.downloadLocation:
            rsInfo["DownloadLocation"] = self.downloadLocation
        if self.sourceRepo:
            rsInfo["SourceRepository"] = self.sourceRepo
        if self.homepage:
            rsInfo["HomePage"] = self.homepage
        if self.releaseTime:
            rsInfo["ReleaseTime"] = self.releaseTime
        if self.builtTime:
            rsInfo["BuiltTime"] = self.builtTime
        if self.validUntilTime:
            rsInfo["ValidUntilTime"] = self.validUntilTime
        return rsInfo


class ValidityInfo:
    def __init__(self, docValidator = None, 
                 docValidationTime = None):
        self.docCreator = "pkg:github/gmscofield/sbomgt@v1.0"
        self.docCreationTime = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.docValidator = docValidator if docValidator else None
        self.docValidationTime = docValidationTime if docValidationTime else None
        self.LicenseListVersion = LicenseListVersion
        self.rsValidityInfo = []
    

    def insert(self, resourceValidityInfo):
        self.rsValidityInfo.append(resourceValidityInfo)


    def toDict(self, level = 1):
        validityInfo = {
            "DocumentCreator": self.docCreator,
            "DocumentCreationTime": self.docCreationTime,
            "LicenseListVersion": self.LicenseListVersion
        }
        if self.docValidator:
            validityInfo["DocumentValidator"] = self.docValidator
        if self.docValidationTime:
            validityInfo["DocumentValidationTime"] = self.docValidationTime
        
        if level == 3:
            validityInfo["ResourceValidityInfo"] = []
            for resource in self.rsValidityInfo:
                if not resource.supplier and not resource.originator and not resource.downloadLocation \
                    and not resource.sourceRepo and not resource.homepage and not resource.releaseTime \
                    and not resource.builtTime and not resource.validUntilTime:
                    continue
                validityInfo["ResourceValidityInfo"].append(resource.toDict())
        
        return validityInfo
