from . import __version__
from .universal import Ref, IDManager


# DocumentInfo class is used to organize document information
class DocumentInfo:
    def __init__(self, docFormat = "OSSBOM", 
                 docName = "OSSBOM Document",
                 docRef = Ref()):
        self.docID = IDManager.get_docID()
        self.docFormat = docFormat
        self.docName = docName
        self.docVersion = __version__
        self.docLicense = "CC0-1.0"
        self.docRef = docRef
        docRef.insert(name = "MulanPSL2", 
                      docURI = "http://license.coscl.org.cn/MulanPSL2"
                    )

    def toDict(self):
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
