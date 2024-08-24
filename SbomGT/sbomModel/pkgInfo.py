from .util import Ref
from typing import Optional, List


class PkgInfo:
    def __init__(
        self, 
        pkgName: Optional[str] = None, 
        pkgID: Optional[str] = None,
        version: Optional[str] = None,
        pkgChecksum: Optional[List] = [], 
        declaredLicense: Optional[str] = None, 
        copyright: Optional[str] = None, 
        properties: Optional[List] = [], 
        pkgRef: Optional[Ref] = Ref()
    ) -> None:
        self.pkgName = pkgName
        self.pkgID = pkgID
        self.pkgVersion = version
        self.pkgChecksum = pkgChecksum
        self.pkgLicense = declaredLicense
        self.copyright = copyright
        self.properties = properties
        self.pkgRef = pkgRef
        self.algoList = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512", 
            "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3", "MD2", "MD4", "MD5", "MD6", "ADLER32"]
    
    def insertChecksum(self, algo: str, checksum: str) -> None:
        if algo not in self.algoList:
            raise ValueError("Invalid checksum algorithm")
        if not checksum:
            raise ValueError("Checksum value is empty")
        if not self.pkgChecksum:
            self.pkgChecksum = []
        self.pkgChecksum.append({"Algorithm": algo, "Checksum": checksum})

    def insertProperties(self, key: str, value: str) -> None:
        self.properties.append(
            {
                "Key": key,
                "Value": value
            }
        )

    def toDict(self) -> dict:
        pkgInfo = {
            "PackageName": self.pkgName,
            "PackageID": self.pkgID
        }
        if self.pkgVersion:
            pkgInfo["PackageVersion"] = self.pkgVersion
        if self.pkgChecksum:
            pkgInfo["PackageChecksum"] = self.pkgChecksum
        if self.pkgLicense:
            pkgInfo["DeclaredLicense"] = self.pkgLicense
        if self.copyright:
            pkgInfo["Copyright"] = self.copyright
        if self.properties:
            pkgInfo["Properties"] = self.properties
        if self.pkgRef.cnt > 0:
            pkgInfo["PackageRef"] = self.pkgRef.docRef
        return pkgInfo


class PkgList:
    def __init__(self) -> None:
        self.pkgList = []
        self.cnt = 0

    def is_existPkg(self, pkgName: str) -> Optional[PkgInfo]:
        for pkg in self.pkgList:
            if pkg.pkgName == pkgName:
                return pkg
        return None

    def insert(self, pkgInfo: PkgInfo) -> None:
        self.pkgList.append(pkgInfo)
        self.cnt += 1

    def toDict(self) -> List[dict]:
        pkgList = []
        for pkg in self.pkgList:
            pkgList.append(pkg.toDict())
        return pkgList
