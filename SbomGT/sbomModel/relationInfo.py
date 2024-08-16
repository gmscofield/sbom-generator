from .universal import IDManager


class RelationshipInfo:
    def __init__(self):
        self.relationshipList = []
        
    def insert(self, relationshipType = None, source = None, target = None):
        if relationshipType == None or source == None or target == None:
            raise ValueError("RelationshipType, Source and Target cannot be empty")
        
        if not relationshipType in ["DependsOn", "Contain", "BuildDepends"]:
            raise ValueError("Invalid RelationshipType")
        
        if not source in IDManager.IDList["rsID"] or not target in IDManager.IDList["rsID"]:
            raise ValueError("Invalid Source or Target")
        
        if not {"ResourceID": source, relationshipType: target} in self.relationshipList:
            self.relationshipList.append({"ResourceID": source, 
                                        relationshipType: target})

    def toDict(self):
        return self.relationshipList