import json
from ...output import middleware
from ..util.utils import Util


class Convert_SBOM:
    def __init__(self, input: str) -> None:
        self.input = input

    def convert_sbom(self) -> middleware.Middleware:
        bom = json.load(open(self.input, "r"))
        midware = Util.choose_model(bom)
        # json.dump(midware.model_dump(mode='json', by_alias=True, exclude_none=True), open("/home/jcg/test/result/convert.json", "w"), indent=4, ensure_ascii=False)
        return midware