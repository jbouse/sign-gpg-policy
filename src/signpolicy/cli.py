import argparse

def create_parser():
    parser = argparse.ArgumentParser(description="Sign and verify a GPG policy file.")
    parser.add_argument("date", help="Date string in YYYYMMDD format")
    parser.add_argument("--dry-run", action="store_true", help="Preview actions without making changes")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    return parser

def parse_arguments():
    parser = create_parser()
    args = parser.parse_args()
    return args
