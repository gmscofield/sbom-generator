from .tool.generate.analyzeSbom import buildBom


__version__ = '1.0'


def generateSBOM(inputPath, level, tree):
    bom = buildBom(inputPath, level, tree)
    return bom.toDict()