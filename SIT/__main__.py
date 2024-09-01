import argparse
import os
from . import __version__
from .tool.generate.analyze_sbom import build_bom
from .tool.convert.convert_sbom import Convert_SBOM
from .tool.export.export_sbom import Export_SBOM
from .tool.merge.merge_sbom import Merge_SBOM
from .tool.util.utils import Util


def get_input() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Software Bill of Materials (SBOM) for a software package.",
        allow_abbrev=False
    )
    parser.add_argument(
        "-v", "--version", 
        action="version", 
        version=__version__
    )
    
    subparsers = parser.add_subparsers(
        title="subcommands",
        metavar="<subcommand>",
        dest="subcmd",
    )
    
    # subcommand: generate SBOM
    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate SBOM for a software package"
    )
    generate_parser.add_argument(
        "-i", "--input", 
        metavar="<INPUT>", 
        type=str, 
        dest="input",
        default=".",
        help="Input path of software package, default is current path",
    )
    generate_parser.add_argument(
        "-o", "--output",
        metavar="<OUTPUT>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
    )
    generate_parser.add_argument(
        "--model", 
        metavar="<MODEL>", 
        type=str,
        dest="model",
        choices=["spdx", "cyclonedx", "ossbom", "middleware"],
        default="middleware",
        help="SBOM Model, choose from SPDX, CycloneDX, OSSBOM or middleware, default is middleware"
    )
    generate_parser.add_argument(
        "--env", 
        metavar="<ENVIRONMENT>",
        type=str,
        dest="env",
        default="",
        help="Running environment of software package, default is None"
    )
    
    # subcommand: merge SBOM
    merge_parser = subparsers.add_parser(
        "merge",
        help="Merge SBOMs"
    )
    merge_parser.add_argument(
        "-i", "--input", 
        metavar="<INPUT>", 
        type=str, 
        dest="input",
        nargs=2,
        required=True,
        help="Input path of SBOMs to be merged, 2 SBOMs are required. The first one is the \
            root SBOM and the second one is sub-SBOM, currently only support json format",
    )
    merge_parser.add_argument(
        "-o", "--output",
        metavar="<OUTPUT>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
    )
    merge_parser.add_argument(
        "--model", 
        metavar="<MODEL>", 
        type=str,
        dest="model",
        choices=["spdx", "cyclonedx", "ossbom", "middleware"],
        default="middleware",
        help="SBOM Model, choose from SPDX, CycloneDX, OSSBOM or middleware, default is middleware"
    )
    
    # subcommand: export SBOM
    export_parser = subparsers.add_parser(
        "export",
        help="Export Sub-SBOM"
    )
    export_parser.add_argument(
        "-i", "--input", 
        metavar="<INPUT>", 
        type=str, 
        dest="input",
        required=True,
        help="Path of SBOM file to be exported",
    )
    export_parser.add_argument(
        "-o", "--output",
        metavar="<OUTPUT>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
    )
    export_parser.add_argument(
        "--id",
        metavar="<ID>",
        type=str,
        dest="id",
        required=True,
        nargs="+",
        help="ID of the top-level Component to be exported",
    )
    export_parser.add_argument(
        "--model", 
        metavar="<MODEL>", 
        type=str,
        dest="model",
        choices=["spdx", "cyclonedx", "ossbom", "middleware"],
        default="middleware",
        help="SBOM Model, choose from SPDX, CycloneDX, OSSBOM or middleware, default is middleware"
    )
    
    # subcommand: convert SBOM
    convert_parser = subparsers.add_parser(
        "convert",
        help="Convert SBOM between different formats"
    )
    convert_parser.add_argument(
        "-i", "--input", 
        metavar="<INPUT>", 
        type=str, 
        dest="input",
        required=True,
        help="Input path of SBOM file to be converted",
    )
    convert_parser.add_argument(
        "-o", "--output",
        metavar="<OUTPUT>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
    )
    convert_parser.add_argument(
        "--model", 
        metavar="<MODEL>", 
        type=str,
        dest="model",
        choices=["spdx", "cyclonedx", "ossbom", "middleware"],
        default="middleware",
        help="SBOM Model, choose from SPDX, CycloneDX, OSSBOM or middleware, default is middleware"
    )
    
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = get_input()
    
    import logging
    from datetime import datetime
    logging.basicConfig(
        format="%(asctime)s (Process %(process)d) [%(levelname)s] %(filename)s:%(lineno)d %(message)s",
        level=logging.INFO,
        filemode="w",
        filename=f"/home/jcg/SBOM/sbom-generator/SIT/log/{args.model}-{datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')}.log"
    )
    
    # print(args.format)
    # print(args.tree)
    
    if args.subcmd == "generate":
        bom = build_bom(args.input, args.env)
    elif args.subcmd == "merge":
        bom = Merge_SBOM(args.input).merge_sbom()
    elif args.subcmd == "export":
        bom = Export_SBOM(args.input, args.id).export_sbom()
    elif args.subcmd == "convert":
        bom = Convert_SBOM(args.input).convert_sbom()
    
    Util.make_output(bom, args.model, args.output)
    logging.info("Successful operation")


# python -m SIT generate -i E:\\code\\SIT\\example\\cyclonedx-python -o E:\\code\\SIT\\result\\sbom.json -f json -l 1

