from .tool.generate.analyze_sbom import build_bom
from typing import Optional


__version__ = '1.0'


def generateSBOM(
    inputPath: str, 
    model: Optional[str] = "middleware", 
    env: Optional[str] = None
):
    bom = build_bom(inputPath, model, env)
    return bom