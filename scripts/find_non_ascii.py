#!/usr/bin/env python3
"""
Script to find and report non-ASCII characters in a file.
For each non-ASCII character found, reports the line number and character offset.
"""

import argparse
import sys


def find_non_ascii_characters(file_path):
    """
    Find all non-ASCII characters in a file and report their positions.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        List of tuples (line_number, char_offset, character, byte_value)
    """
    non_ascii_chars = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, start=1):
                for char_offset, char in enumerate(line):
                    if ord(char) > 127:  # Non-ASCII character
                        non_ascii_chars.append((line_num, char_offset, char, ord(char)))
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading '{file_path}'.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    return non_ascii_chars


def main():
    parser = argparse.ArgumentParser(
        description='Find and report non-ASCII characters in a file.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.txt
  %(prog)s --verbose source_code.c
        """
    )
    
    parser.add_argument(
        'file',
        help='Path to the file to analyze'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including byte values'
    )
    
    args = parser.parse_args()
    
    # Find non-ASCII characters
    non_ascii_chars = find_non_ascii_characters(args.file)
    
    # Report results
    if not non_ascii_chars:
        print(f"No non-ASCII characters found in '{args.file}'")
        return 0
    
    print(f"Found {len(non_ascii_chars)} non-ASCII character(s) in '{args.file}':\n")
    
    for line_num, char_offset, char, byte_value in non_ascii_chars:
        if args.verbose:
            # Show character representation, handling unprintable characters
            char_repr = repr(char)
            print(f"Line {line_num}, Column {char_offset}: {char_repr} (U+{byte_value:04X}, decimal {byte_value})")
        else:
            print(f"Line {line_num}, Column {char_offset}: {repr(char)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
