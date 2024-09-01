from typing import Optional, List
from .util import Ref


class InnerInfo:
    def __init__(self, 
        innerType: str = "FILE", 
        innerName: Optional[str] = None, 
        innerID: Optional[str] = None,
        location: Optional[str] = None,
        innerChecksum: Optional[List] = None, 
        declaredLicense: Optional[str] = None, 
        copyright: Optional[str] = None, 
        innerRef: Optional[Ref] = Ref()
    ) -> None:
        self.innerType = innerType
        self.innerName = innerName
        self.innerID = innerID
        self.innerLocation = location
        self.innerChecksum = innerChecksum
        self.innerLicense = declaredLicense if declaredLicense else None
        self.copyright = copyright
        self.innerRef = innerRef
        self.algoList = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512", 
            "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3", "MD2", "MD4", "MD5", "MD6", "ADLER32"]
    
    def insertChecksum(self, algo: str, checksum: str) -> None:
        if algo not in self.algoList:
            raise ValueError("Invalid checksum algorithm")
        if not checksum:
            raise ValueError("Checksum value is empty")
        if not self.innerChecksum:
            self.innerChecksum = []
        self.innerChecksum.append({"Algorithm": algo, "Checksum": checksum})

    def toDict(self) -> dict:
        innerInfo = {
            "InnerType": self.innerType,
            "InnerName": self.innerName,
            "InnerID": self.innerID,
            "InnerLocation": self.innerLocation
        }
        if self.innerChecksum:
            innerInfo["InnerChecksum"] = self.innerChecksum
        if self.innerLicense:
            innerInfo["DeclaredLicense"] = self.innerLicense
        if self.copyright:
            innerInfo["Copyright"] = self.copyright
        if self.innerRef.cnt > 0:
            innerInfo["InnerRef"] = self.innerRef.docRef
        return innerInfo


class InnerList:
    def __init__(self) -> None:
        self.innerList = []
        self.cnt = 0

    def insert(self, innerInfo: InnerInfo) -> None:
        self.innerList.append(innerInfo)
        self.cnt += 1
    
    def is_existInner(self, innerName: str) -> bool:
        for inner in self.innerList:
            if inner.innerName == innerName:
                return True
        return False

    def toDict(self) -> List:
        if self.cnt == 0:
            return None
        innerList = []
        for inner in self.innerList:
            innerList.append(inner.toDict())
        return innerList
