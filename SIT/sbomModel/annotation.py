from datetime import datetime


class Annotation:
    def __init__(self) -> None:
        self.cnt = 0
        self.annotationList = []
    
    def insert(self, annotationID: str, annotator: str, annotationText: str) -> None:
        self.annotationList.append(
            {
                "AnnotationID": annotationID,
                "Annotator": annotator,
                "AnnotationTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "AnnotationText": annotationText
            }
        )
        self.cnt += 1

    def toDict(self) -> list:
        return self.annotationList
        