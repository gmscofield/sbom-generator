import argparse
from . import __version__
from .tool.generate.analyzeSbom import buildBom, makeBOM


def get_input(argv=None):
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
        "-o", "--outfile",
        metavar="<OUTFILE>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
    )
    generate_parser.add_argument(
        "-f", "--format",
        metavar="<FORMAT>",
        type=str,
        dest="format",
        choices=["txt", "json", "yaml"],
        default="txt",
        help="Output format of SBOM, choose from txt or json, default is txt"
    )
    generate_parser.add_argument(
        "--model", 
        metavar="<MODEL>", 
        type=str,
        dest="model",
        choices=["spdx", "cyclonedx", "ossbom"],
        default="ossbom",
        help="SBOM Model, choose from SPDX, CycloneDX or OSSBOM, default is OSSBOM"
    )
    generate_parser.add_argument(
        "-l", "--level",
        metavar="<SBOM LEVEL>", 
        type=int,
        dest="level",
        choices=[1, 2, 3],
        default=1,
        help="SBOM level, choose from 1, 2 or 3, \
            default is basic level of SBOM (Level 1)"
    )
    generate_parser.add_argument(
        "--tree", 
        action="store_true",
        help="Present the whole Dependency Tree in the SBOM document",
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
        default=".",
        help="Input path of software package, default is current path",
    )
    merge_parser.add_argument(
        "-o", "--outfile",
        metavar="<OUTFILE>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
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
        default=".",
        help="Input path of software package, default is current path",
    )
    export_parser.add_argument(
        "-o", "--outfile",
        metavar="<OUTFILE>", 
        type=str, 
        dest="output",
        default="-",
        help="Output file path of SBOM, default is stdout"
    )

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = get_input()
    # print(args.format)
    # print(args.level)
    # print(args.tree)

    
    # 返回的是OSSBOM类对象
    if args.subcmd == "generate":
        bom = buildBom(args.input, args.level, args.tree)
        makeBOM(bom, args.output, args.format, args.model)
    elif args.subcmd == "merge":
        print(args)
    elif args.subcmd == "export":
        print(args)
    
    
    # pkg = PkgInfo()
    # pkgList = PkgList()
    # pkgList.addPkg(pkg)
    # bom = OSSBOM(level=args.level, pkgList=pkgList)
    # bom.makeBOM(args.outPath, args.format)
    # print(IDManager.IDList)


# 运行: python -m SbomGT -i E:\\code\\SbomGT\\example\\cyclonedx-python -o E:\\code\\SbomGT\\result\\sbom.json -f json -l 1
