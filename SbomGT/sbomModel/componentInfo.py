from .universal import Ref, IDManager
# from .License import License


class ComponentInfo:
    def __init__(self, componentType = "FILE", 
                 componentName = None, 
                 componentID = IDManager.get_componentID(),
                 location = None,
                 componentChecksum = None, 
                 declaredLicense = None, 
                 copyright = None, 
                 componentRef = Ref()):
        self.componentType = componentType
        self.componentName = componentName
        self.componentID = componentID
        self.componentLocation = location
        self.componentChecksum = componentChecksum
        self.componentLicense = declaredLicense if declaredLicense else None
        self.copyright = copyright
        self.componentRef = componentRef
        self.algoList = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", 
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", 
        "BLAKE2b-512", "BLAKE3", "MD2", "MD4", "MD5", "MD6", "ADLER32"]
    
    def insertChecksum(self, algo, checksum):
        if algo not in self.algoList:
            raise ValueError("Invalid checksum algorithm")
        if not checksum:
            raise ValueError("Checksum value is empty")
        if not self.componentChecksum:
            self.componentChecksum = []
        self.componentChecksum.append({"Algorithm": algo, "Checksum": checksum})

    def toDict(self):
        componentInfo = {
            "ComponentType": self.componentType,
            "ComponentName": self.componentName,
            "ComponentID": self.componentID,
            "ComponentLocation": self.componentLocation
        }
        if self.componentChecksum:
            componentInfo["ComponentChecksum"] = self.componentChecksum
        if self.componentLicense:
            componentInfo["DeclaredLicense"] = self.componentLicense
        if self.copyright:
            componentInfo["Copyright"] = self.copyright
        if self.componentRef.cnt > 0:
            componentInfo["ComponentRef"] = self.componentRef.docRef
        return componentInfo


class ComponentList:
    def __init__(self):
        self.componentList = []
        self.cnt = 0

    def insert(self, componentInfo):
        self.componentList.append(componentInfo)
        self.cnt += 1
    
    def is_existComponent(self, componentName):
        for component in self.componentList:
            if component.componentName == componentName:
                return True
        return False

    def toDict(self):
        if self.cnt == 0:
            return None
        componentList = []
        for component in self.componentList:
            componentList.append(component.toDict())
        return componentList
