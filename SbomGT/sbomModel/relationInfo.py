from typing import Optional

class RelationshipInfo:
    def __init__(self) -> None:
        self.relationshipList = []
        
    def insert(
        self, 
        relationshipType: Optional[str] = None, 
        source: Optional[str] = None, 
        target: Optional[str] = None
    ) -> None:
        if relationshipType == None or source == None or target == None:
            raise ValueError("RelationshipType, Source and Target cannot be empty")
        
        if not relationshipType in ["DependsOn", "Contain", "BuildDepends"]:
            raise ValueError("Invalid RelationshipType")
        
        if not {"ResourceID": source, relationshipType: target} in self.relationshipList:
            self.relationshipList.append({"ResourceID": source, 
                                        relationshipType: target})

    def toDict(self) -> list:
        return self.relationshipList