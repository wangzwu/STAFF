import os
import sys

TARGET_SUBDIR = "crashes"
DELIMITER = b"\x1a" * 4
SUBSTRINGS_TO_REMOVE = [b'.gif', b'.css', b'.jpeg', b'.jpg', b'.png', b'.css', b'.js', b'.ico']

def should_remove(request: bytes) -> bool:
    return any(sub in request for sub in SUBSTRINGS_TO_REMOVE)

def process_file(file_path):
    with open(file_path, "rb") as f:
        content = f.read()

    requests = content.split(DELIMITER)
    filtered = [req for req in requests if not should_remove(req)]

    with open(file_path, "wb") as f:
        f.write(DELIMITER.join(filtered))

def walk_and_process(base_dir):
    for root, _, files in os.walk(base_dir):
        if os.path.basename(root) == TARGET_SUBDIR:
            for fname in files:
                if fname.startswith("id"):
                    full_path = os.path.join(root, fname)
                    process_file(full_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <base_dir>")
        sys.exit(1)

    base_dir = sys.argv[1]
    if not os.path.isdir(base_dir):
        print(f"Error: {base_dir} is not a valid directory.")
        sys.exit(1)

    walk_and_process(base_dir)
    print("Processing complete.")
