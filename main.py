import argparse
import logging
import os
import re
import math
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define suspicious string patterns (expand as needed)
SUSPICIOUS_PATTERNS = [
    re.compile(r";\s*(rm|del)\s+-rf", re.IGNORECASE),  # rm -rf or del /f /q /s
    re.compile(r"eval\(", re.IGNORECASE),  # eval() usage
    re.compile(r"exec\(", re.IGNORECASE),  # exec() usage
    re.compile(r"subprocess\.call\(", re.IGNORECASE),  # subprocess.call() usage
    re.compile(r"os\.system\(", re.IGNORECASE),  # os.system() usage
    re.compile(r"\.\./", re.IGNORECASE),  # Path traversal
    re.compile(r"/etc/passwd", re.IGNORECASE), # potential password access
    re.compile(r"UNION\s+SELECT", re.IGNORECASE), # sql injection
]


def calculate_entropy(data):
    """
    Calculates the entropy of a string.
    Lower entropy might indicate a simple, predictable string; higher entropy could suggest randomness or encryption.
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def scan_file(filename, entropy_threshold=4.5):
    """
    Scans a file for suspicious strings and high-entropy strings.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()  # Remove leading/trailing whitespace
                # Check for suspicious patterns
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(line):
                        logging.warning(f"[{filename}:{line_number}] Suspicious pattern detected: {line}")
                        print(f"[{filename}:{line_number}] Suspicious pattern detected: {line}")

                # Check for high-entropy strings (longer than 10 characters)
                if len(line) > 10:
                    entropy = calculate_entropy(line)
                    if entropy > entropy_threshold:
                        logging.warning(f"[{filename}:{line_number}] High entropy string detected (entropy={entropy:.2f}): {line}")
                        print(f"[{filename}:{line_number}] High entropy string detected (entropy={entropy:.2f}): {line}")

    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        print(f"Error: File not found: {filename}")
        return 1
    except IOError as e:
        logging.error(f"Error reading file {filename}: {e}")
        print(f"Error reading file {filename}: {e}")
        return 1
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        return 1

    return 0


def scan_directory(directory, entropy_threshold=4.5):
    """
    Recursively scans a directory for suspicious strings.
    """
    return_code = 0
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            return_code |= scan_file(filepath, entropy_threshold) #bitwise OR to check if any file has errors
    return return_code


def setup_argparse():
    """
    Sets up the argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans code for potentially malicious or suspicious strings.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to the file to scan.")
    group.add_argument("-d", "--directory", help="Path to the directory to scan (recursively).")
    parser.add_argument("-e", "--entropy_threshold", type=float, default=4.5,
                        help="Entropy threshold for detecting high-entropy strings (default: 4.5).")
    parser.add_argument("-l", "--log_file", help="Path to the log file. If not provided, logs will be printed to the console.")
    return parser


def main():
    """
    Main function.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.log_file:
        # Configure logging to file if specified
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(file_handler)

    try:
        if args.file:
            return_code = scan_file(args.file, args.entropy_threshold)
        elif args.directory:
            return_code = scan_directory(args.directory, args.entropy_threshold)
        else:
            logging.error("No file or directory specified.")
            print("Error: No file or directory specified.")
            return_code = 1

        if return_code != 0:
          print("Errors detected.  See log for details.")

        sys.exit(return_code) # Indicate errors via exit code
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)

# Example usage
if __name__ == "__main__":
    # Example 1: Scan a single file
    # python suspicious_string_detector.py -f example.py

    # Example 2: Scan a directory
    # python suspicious_string_detector.py -d ./my_project

    # Example 3: Scan a file with a custom entropy threshold
    # python suspicious_string_detector.py -f example.py -e 5.0

    # Example 4: Scan a directory and log the results to a file
    # python suspicious_string_detector.py -d ./my_project -l scan.log

    # Example 5: If the file or directory is specified as a relative path, it must be relative to the location the script is executed from.
    # For example, to execute the script from /home/user and analyze a file located in /home/user/projects/my_project/example.py, you would run:
    # python suspicious_string_detector.py -f projects/my_project/example.py
    main()