from typing import Optional
from . import __version__
from .util import Ref


# DocumentInfo class is used to organize document information
class DocumentInfo:
    def __init__(
        self, 
        docFormat: str = "OSSBOM", 
        docName: str = "OSSBOM Document",
        docID: Optional[str] = None,
        docRef: Optional[Ref] = Ref()
    ) -> None:
        self.docID = docID
        self.docFormat = docFormat
        self.docName = docName
        self.docVersion = __version__
        self.docLicense = "CC0-1.0"
        self.docRef = docRef
        docRef.insert(
            name = "MulanPSL2", 
            docURI = "http://license.coscl.org.cn/MulanPSL2"
        )

    def toDict(self) -> dict:
        docInfo = {
            "DocumentFormat": self.docFormat,
            "DocumentName": self.docName,
            "DocumentVersion": self.docVersion,
            "DocumentID": self.docID,
            "DocumentLicense": self.docLicense
        }
        if self.docRef.cnt > 0:
            docInfo["DocumentRef"] = self.docRef.docRef
        return docInfo
