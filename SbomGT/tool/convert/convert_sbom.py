import json
from ..util.utils import Util


class Convert_SBOM:
    def __init__(self, input: str, output: str, model: str) -> None:
        self.input = input
        self.output = output
        self.model = model

    def convert_sbom(self) -> None:
        bom = json.load(open(self.input, "r"))
        midware = Util.choose_model(bom)
        Util.make_output(midware, self.model, self.output)