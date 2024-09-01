import sys
sys.path.append("..")
from fastapi import FastAPI, Query
from typing import Optional, Literal, List
from pydantic import BaseModel, Field
from SIT.tool.generate.analyze_sbom import build_bom
from SIT.tool.convert.convert_sbom import Convert_SBOM
from SIT.tool.export.export_sbom import Export_SBOM
from SIT.tool.merge.merge_sbom import Merge_SBOM
from SIT.tool.util.utils import Util
from fastapi.openapi.utils import get_openapi
import yaml
from collections import OrderedDict


class Response(BaseModel):
    message: str = Field(
        ...,
        title="Response Message",
        description="The response message of the request"
    )
    sbom: Optional[dict] = Field(
        None,
        title="Software Bill of Materials",
        description="The software bill of materials in SPDX, CycloneDX, OSSBOM or middleware format"
    )


app = FastAPI()


@app.get("/generate", status_code=200)
def generate_sbom(
    input: str = Query(...), 
    output: Optional[str] = Query(None), 
    model: Literal["spdx", "cyclonedx", "ossbom", "middleware"] = Query("middleware"),
    env: Optional[str] = Query(None)
) -> Response:
    bom = build_bom(input, env)
    res = Response(message="SBOM generated successfully! ")
    if output:
        Util.make_output(bom, model, output)
        res.message += f"Save SBOM to {output}"

    res.sbom = Util.convert2model(bom, model)
    return res


@app.get("/merge", status_code=200)
def merge_sbom(
    input: List[str] = Query(..., min_length=2, max_length=2), 
    output: Optional[str] = Query(None), 
    model: Literal["spdx", "cyclonedx", "ossbom", "middleware"] = Query("middleware"),
):
    bom = Merge_SBOM(input).merge_sbom()
    res = Response(message="SBOM merged successfully! ")
    if output:
        Util.make_output(bom, model, output)
        res.message += f"Save SBOM to {output}"
    
    res.sbom = Util.convert2model(bom, model)
    return res
    

@app.get("/export", status_code=200)
def export_sbom(
    input: str = Query(...), 
    output: Optional[str] = Query(None), 
    model: Literal["spdx", "cyclonedx", "ossbom", "middleware"] = Query("middleware"),
    id: List[str] = Query(...),
):
    bom = Export_SBOM(input, id).export_sbom()
    res = Response(message="SBOM exported successfully! ")
    if output:
        Util.make_output(bom, model, output)
        res.message += f"Save SBOM to {output}"
    
    res.sbom = Util.convert2model(bom, model)
    return res


@app.get("/convert", status_code=200)
def convert_sbom(
    input: str = Query(...), 
    output: Optional[str] = Query(None), 
    model: Literal["spdx", "cyclonedx", "ossbom", "middleware"] = Query("middleware"),
):
    bom = Convert_SBOM(input).convert_sbom()
    res = Response(message="SBOM converted successfully! ")
    if output:
        Util.make_output(bom, model, output)
        res.message += f"Save SBOM to {output}"
    
    res.sbom = Util.convert2model(bom, model)
    return res


# def ordered_dict_representer(dumper, data):
#     return dumper.represent_dict(data.items())

# yaml.add_representer(OrderedDict, ordered_dict_representer, Dumper=yaml.SafeDumper)

# def generate_openapi_yaml():
#     openapi_schema = get_openapi(
#         title="SBOM Integration Tool",
#         version="1.0.0",
#         description="A tool for generating, merging, exporting and converting Software Bill of Materials (SBOM)",
#         routes=app.routes,
#     )
    
#     openapi_schema_ordered = OrderedDict(**openapi_schema)
#     with open("openapi.yaml", "w") as f:
#         yaml.dump(openapi_schema_ordered, f, Dumper=yaml.SafeDumper, allow_unicode=True, default_flow_style=False)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9002)
    # generate_openapi_yaml()