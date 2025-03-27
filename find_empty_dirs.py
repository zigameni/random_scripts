import os

# Get the current directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(script_dir, "empty_dirs.txt")

# Get the user's home directory
home_dir = os.path.expanduser("~")

# List of directories to exclude (relative to home_dir)
excluded_dirs = {"AppData", ".git"}

# Find empty directories, excluding system folders
empty_dirs = []
for root, dirs, files in os.walk(home_dir):
    # Get the relative path from home_dir
    relative_path = os.path.relpath(root, home_dir)
    
    # Skip if it's in the excluded directories list
    if any(relative_path.startswith(excluded) for excluded in excluded_dirs):
        continue

    if not dirs and not files:  # Check if directory is empty
        empty_dirs.append(root)

# Save empty directories to file
with open(output_file, "w", encoding="utf-8") as f:
    for directory in empty_dirs:
        f.write(directory + "\n")

print(f"Empty directories list saved to {output_file}")
