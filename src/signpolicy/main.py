from .cli import parse_arguments
from .utils import process_policy

def main():
    args = parse_arguments()

    process_policy(args.date, dry_run=args.dry_run, no_color=args.no_color)

if __name__ == "__main__":
    main()
