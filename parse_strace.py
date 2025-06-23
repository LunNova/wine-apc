#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 LunNova
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import re
import sys
import os
from collections import Counter, defaultdict


def parse_strace_log(filename):
    """Parse strace log and extract Wine server requests"""

    # Load the wine request mappings
    wine_requests = {}
    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/wine-REQ-list.md", "r") as f:
            for line in f:
                if "//" in line and "REQ_" in line:
                    parts = line.strip().split("//")
                    if len(parts) == 2:
                        req_name = parts[0].strip()
                        req_id = parts[1].strip()
                        try:
                            wine_requests[int(req_id)] = req_name
                        except ValueError:
                            pass
    except FileNotFoundError:
        print("Warning: wine-REQ-list.md not found, will show raw request IDs")

    request_counts = Counter()
    request_details = defaultdict(list)

    # Parse the strace log
    with open(filename, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Look for write calls to Wine server (typically 64 bytes)
            write_match = re.search(r'write\((\d+), "([^"]*)".*?, 64\) = 64', line)

            # Also look for writev calls that contain Wine requests
            writev_match = re.search(
                r'writev\((\d+), \[\{iov_base="([^"]*)".*?\}\]', line
            )

            # Process either write or writev match
            match_data = None
            if write_match:
                match_data = (int(write_match.group(1)), write_match.group(2))
            elif writev_match:
                match_data = (int(writev_match.group(1)), writev_match.group(2))

            if match_data:
                fd, data = match_data

                # Extract first byte as request ID (Wine requests start with request ID)
                if data:
                    try:
                        req_id = parse_first_byte(data)
                        if req_id is not None:
                            req_name = wine_requests.get(req_id, f"UNKNOWN_{req_id}")
                            request_counts[req_id] += 1
                            request_details[req_id].append(
                                {
                                    "line": line_num,
                                    "fd": fd,
                                    "data_preview": (
                                        data[:32] + "..." if len(data) > 32 else data
                                    ),
                                }
                            )

                    except (ValueError, IndexError):
                        pass

    return request_counts, request_details, wine_requests


def parse_first_byte(data_str):
    """Parse the first byte from strace data string, handling various formats"""
    if not data_str:
        return None

    # Handle escape sequences at the start
    if data_str.startswith("\\"):
        # Check for octal escape (1-3 digits)
        octal_match = re.match(r"\\([0-7]{1,3})", data_str)
        if octal_match:
            return int(octal_match.group(1), 8)
        elif data_str.startswith("\\x") and len(data_str) >= 4:
            # Hex escape like \x13
            try:
                return int(data_str[2:4], 16)
            except ValueError:
                return None
        elif data_str.startswith("\\n"):
            return ord("\n")
        elif data_str.startswith("\\t"):
            return ord("\t")
        elif data_str.startswith("\\r"):
            return ord("\r")
        elif data_str.startswith("\\\\"):
            return ord("\\")
        elif data_str.startswith('\\"'):
            return ord('"')
        else:
            # Unknown escape, skip
            return None
    else:
        # Literal character
        return ord(data_str[0])


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parse_strace.py <strace_log_file>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        counts, details, wine_reqs = parse_strace_log(filename)

        print("=== Wine Server Request Summary ===")

        if not counts:
            print("No Wine server requests found in the log.")
            return

        print(f"Found {sum(counts.values())} total Wine requests:")
        print()

        # Sort by frequency
        for req_id, count in counts.most_common():
            req_name = wine_reqs.get(req_id, f"UNKNOWN_{req_id}")
            print(
                f"Request {req_id:3d} (0x{req_id:02x}): {count:4d} calls - {req_name}"
            )

        print()
        print("=== First few examples of each request type ===")

        for req_id in sorted(counts.keys()):
            req_name = wine_reqs.get(req_id, f"UNKNOWN_{req_id}")
            examples = details[req_id][:3]  # First 3 examples

            print(f"Request {req_id} ({req_name}):")
            for example in examples:
                print(
                    f"  Line {example['line']:5d}: fd={example['fd']}, data={example['data_preview']}"
                )
            if len(details[req_id]) > 3:
                print(f"  ... and {len(details[req_id]) - 3} more")
            print()

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
