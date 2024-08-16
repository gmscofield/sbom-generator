from uuid import uuid4
from packageurl import PackageURL
from packageurl.contrib import url2purl


class IDManager:
    IDList = {"docID": [], 
              "rsID": [],
              "licenseID": []
            }
    
    @staticmethod
    def get_uuid():
        idstring = uuid4()
        return f"urn:uuid:{idstring}"

    @staticmethod
    def get_docID():
        idstring = IDManager.get_uuid()
        IDManager.IDList["docID"].append(idstring)
        return idstring

    @staticmethod
    def get_pkgID(pkgtype = None, namespace = None, name = None, 
            version = None, qualifiers = None, subpath = None, url = None):
        if pkgtype is None and name is None:
            idstring = IDManager.get_uuid()
        else:
            if url:
                temID = url2purl.get_purl(url)
                if not pkgtype:
                    pkgtype = temID.type
                if not namespace:
                    namespace = temID.namespace
                if not name:
                    name = temID.name
                if not version:
                    version = temID.version
                if not qualifiers:
                    qualifiers = temID.qualifiers
                if not subpath:
                    subpath = temID.subpath
                idstring = PackageURL(type = pkgtype, namespace = namespace, name = name, 
                        version = version, qualifiers = qualifiers, subpath = subpath).to_string()
            else:
                idstring = IDManager.get_uuid()
        IDManager.IDList["rsID"].append(idstring)
        return idstring
    
    @staticmethod
    def is_existID(idtype, idstring):
        if idstring in IDManager.IDList[idtype]:
            return True
        return False

    @staticmethod
    def get_componentID():
        idstring = IDManager.get_uuid()
        IDManager.IDList["rsID"].append(idstring)
        return idstring
    
    @staticmethod
    def get_licenseID():
        idstring = IDManager.get_uuid()
        IDManager.IDList["licenseID"].append(idstring)
        return idstring
    
    @staticmethod
    def merge_pkgID(pkgID1, pkgID2):
        if pkgID1 and pkgID2:
            if pkgID1.startswith("pkg:"):
                return pkgID1
            elif pkgID2.startswith("pkg:"):
                return pkgID2
            return pkgID1
        else:
            return (pkgID1 or pkgID2)
        
    

class Ref:
    def __init__(self):
        self.docRef = []
        self.cnt = 0
    
    def insert(self, name = None, docURI = None):
        if name == None or docURI == None:
            return
        
        newRef = {
            "Name": name, 
            "DocumentURI": docURI
        }
        self.docRef.append(newRef)
        self.cnt += 1

    def extend(self, ref):
        if not ref or not ref.cnt:
            return
        for doc in ref.docRef:
            if doc in self.docRef:
                continue
            self.docRef.append(doc)
            self.cnt += 1
