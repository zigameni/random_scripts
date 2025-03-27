import os

# Get the current directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
input_file = os.path.join(script_dir, "empty_dirs.txt")

# Check if the file exists
if os.path.exists(input_file):
    with open(input_file, "r", encoding="utf-8") as f:
        empty_dirs = f.read().splitlines()

    # Delete only if the directory is still empty
    deleted_count = 0
    for directory in empty_dirs:
        if os.path.exists(directory) and not os.listdir(directory):  # Double-check if still empty
            os.rmdir(directory)
            print(f"Deleted: {directory}")
            deleted_count += 1
        else:
            print(f"Skipped (not empty): {directory}")

    # Remove the list file only if all directories were deleted
    if deleted_count == len(empty_dirs):
        os.remove(input_file)
        print("All empty directories deleted. Cleanup file removed.")
    else:
        print("Some directories were not deleted (not empty or missing). Cleanup file kept.")

else:
    print(f"No file found at {input_file}")
