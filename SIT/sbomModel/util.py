from typing import Literal, Optional
import os
import sys


class Ref:
    def __init__(self) -> None:
        self.docRef = []
        self.cnt = 0
    
    def insert(self, name: Optional[str] = None, docURI: Optional[str] = None) -> None:
        if name == None or docURI == None:
            return
        
        newRef = {
            "Name": name, 
            "DocumentURI": docURI
        }
        self.docRef.append(newRef)
        self.cnt += 1

    def extend(self, ref: Optional["Ref"]) -> None:
        if not ref or not ref.cnt:
            return
        for doc in ref.docRef:
            if doc in self.docRef:
                continue
            self.docRef.append(doc)
            self.cnt += 1


def ossbom_output(
    bomInfo: dict, 
    filepath: str = "-", 
    fileformat: Literal["txt", "json", "yaml"] = "txt"
) -> None:
    if filepath != "-":
        if not filepath.endswith("." + fileformat):
            filepath = os.path.join(filepath, "ossbom." + fileformat)
        head, tail = os.path.split(filepath)
        if not os.path.exists(head):
            os.makedirs(head)
        IOwriter = open(filepath, "w")
    else:
        IOwriter = sys.stdout
    
    format2output = {
        "txt": bomInfo.toTXT,
        "json": bomInfo.toJSON,
        "yaml": bomInfo.toYAML
    }
    
    format2output[fileformat](IOwriter)
    
    if filepath != "-":
        bomInfo.toHash(filepath)
    if not ".json" in filepath:
        file = open(os.path.join(os.path.dirname(filepath), "ossbom", ".json"), "w")
        bomInfo.toJSON(file)
        file.close()