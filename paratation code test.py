#!/usr/bin/env python3
"""
partition_analysis.py

Simple partition table analyser for a RAW disk image (.dd).

- Reads the first 512 bytes (MBR) of the image.
- Extracts the 4 partition entries from the partition table.
- Prints human-readable information for each real partition.
- Highlights the SECOND real partition separately (for coursework Task 1).

Does NOT use pytsk3 – only Python standard library.
"""

import argparse
import os
import struct
from typing import List, Dict

SECTOR_SIZE = 512   # Standard MBR sector size – first 512 bytes contain the partition table


def parse_mbr(mbr_bytes: bytes) -> List[Dict]:
    """
    Parse the 512-byte MBR and return a list of partition dictionaries.
    Each dict represents one of the four possible partition entries.

    The MBR layout is:
    - 0–445 bytes: Bootloader code
    - 446–509 bytes: 4 partition entries (16 bytes each)
    - 510–511 bytes: Signature (0x55AA)
    """
    if len(mbr_bytes) != SECTOR_SIZE:
        raise ValueError("MBR must be exactly 512 bytes")

    # The last two bytes of a valid MBR must be 0x55 0xAA
    signature = mbr_bytes[510:512]
    if signature != b"\x55\xaa":
        print("[!] Warning: MBR signature 0x55AA not found. "
              "Image may not use a standard MBR (could be GPT or a volume-only image).")

    partitions: List[Dict] = []

    print("\n--- Raw MBR partition entries (debug) ---")
    # There are always 4 entries in an MBR partition table
    for i in range(4):
        offset = 446 + i * 16      # Where each partition entry starts
        entry = mbr_bytes[offset:offset + 16]

        # Each entry is structured as:
        # status (1 byte), first CHS (3 bytes), type (1 byte),
        # last CHS (3 bytes), start LBA (4 bytes), number of sectors (4 bytes)
        status, first_chs, part_type, last_chs, start_lba, num_sectors = struct.unpack(
            "<B3sB3sII", entry
        )

        # This debug line prints every raw entry so you can see what the table contains
        print(
            f"Entry {i}: status=0x{status:02X}, type=0x{part_type:02X}, "
            f"start_lba={start_lba}, sectors={num_sectors}"
        )

        # If type = 0x00 OR number of sectors = 0 → it’s an empty/unused entry
        if part_type == 0x00 or num_sectors == 0:
            continue   # skip it

        # A status byte of 0x80 means bootable
        is_bootable = (status == 0x80)

        size_bytes = num_sectors * SECTOR_SIZE
        size_gb = size_bytes / (1024 ** 3)

        # Store extracted info as a Python dictionary
        partitions.append(
            {
                "table_index": i,  
                "bootable": is_bootable,
                "type": part_type,
                "start_lba": start_lba,        # where this partition begins on disk
                "num_sectors": num_sectors,    # size in sectors
                "size_bytes": size_bytes,      # size in bytes
                "size_gb": size_gb,            # size in gigabytes
            }
        )

    if not partitions:
        # If we reach this, the table contains no valid partitions
        print("\n[!] No non-empty partition entries found in the MBR.")
        print("    This often means the image is a single volume/partition,")
        print("    or it uses a different partitioning scheme.")
    print("-----------------------------------------\n")

    return partitions


def type_description(part_type: int) -> str:
    """
    Maps common MBR partition type codes to human-readable names.
    Not every code is included, but the most common ones are.
    """
    mapping = {
        0x07: "NTFS/exFAT/HPFS (0x07)",
        0x0B: "W95 FAT32 (0x0B)",
        0x0C: "W95 FAT32 LBA (0x0C)",
        0x0E: "W95 FAT16 LBA (0x0E)",
        0x83: "Linux (0x83)",
        0x82: "Linux Swap (0x82)",
        0xEE: "GPT protective MBR (0xEE)",  # If disk uses GPT, MBR type will be EE
    }
    return mapping.get(part_type, f"Unknown / Other (0x{part_type:02X})")


def print_partition_info(partitions: List[Dict]) -> None:
    """
    Prints a readable summary of partitions.
    Also creates a dedicated highlight section for the second real partition.
    """
    print("=== Partition Table Analysis ===\n")

    if not partitions:
        print("No real partitions found (all entries empty or zero-length).")
        return

    # Loop through each detected real partition
    for idx, p in enumerate(partitions, start=1):
        print(f"Partition #{idx}")
        print(f"  MBR Table Index  : {p['table_index']} (0–3)")
        print(f"  Bootable         : {'Yes' if p['bootable'] else 'No'}")
        print(f"  Type             : {type_description(p['type'])}")
        print(f"  Start LBA        : {p['start_lba']}")
        print(f"  Length (sectors) : {p['num_sectors']}")
        print(f"  Size (bytes)     : {p['size_bytes']}")
        print(f"  Size (GB)        : {p['size_gb']:.2f}")
        print()

    # Coursework requires a "second partition check"
    if len(partitions) >= 2:
        second = partitions[1]  # second real partition
        print("=== DETAILS FOR SECOND REAL PARTITION ===")
        print(f"  Logical #        : 2")
        print(f"  MBR Table Index  : {second['table_index']}")
        print(f"  Bootable         : {'Yes' if second['bootable'] else 'No'}")
        print(f"  Type             : {type_description(second['type'])}")
        print(f"  Start LBA        : {second['start_lba']}")
        print(f"  Length (sectors) : {second['num_sectors']}")
        print(f"  Size (bytes)     : {second['size_bytes']}")
        print(f"  Size (GB)        : {second['size_gb']:.2f}")
        print()
    else:
        print("=== No second real partition found to highlight. ===\n")

    # Identify which partition is the largest
    largest = max(partitions, key=lambda x: x["size_bytes"])
    largest_index = partitions.index(largest) + 1  # convert 0-based to human readable

    print("=== Summary ===")
    print(f"  Total real partitions found : {len(partitions)}")
    print(f"  Largest partition           : #{largest_index} "
          f"({largest['size_gb']:.2f} GB, type {type_description(largest['type'])})")


def analyze_image(image_path: str) -> None:
    """
    Opens the image, reads the first 512 bytes (MBR), and passes
    the data to the parser + printing function.
    """
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    size_bytes = os.path.getsize(image_path)       # size of entire image file
    size_gb = size_bytes / (1024 ** 3)
    print(f"Opened image: {image_path}")
    print(f"Image size   : {size_bytes} bytes (~{size_gb:.2f} GB)\n")

    with open(image_path, "rb") as f:
        mbr = f.read(SECTOR_SIZE)   # read only the first 512 bytes = MBR

    partitions = parse_mbr(mbr)     # analyze the partition table
    print_partition_info(partitions)


def main():
    """
    Handles argument parsing AND interactive input fallback.
    This makes the script usable both from:
    - Terminal with: python script.py -i "image.dd"
    - VS Code Run button (asks for input)
    """
    parser = argparse.ArgumentParser(
        description="Simple MBR partition table analyser for RAW disk images."
    )
    parser.add_argument(
        "-i",
        "--image",
        required=False,   # Not forced because of interactive fallback
        help="Path to the RAW disk image (.dd)",
    )
    args = parser.parse_args()

    image_path = args.image

    # If no path was given, ask the user manually
    if not image_path:
        print("No --image argument provided.")
        image_path = input("Enter full path to the RAW image (.dd): ").strip().strip('"')

    try:
        analyze_image(image_path)
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
