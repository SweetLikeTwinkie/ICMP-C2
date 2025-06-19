#!/bin/bash

# Setup Git for ICMP C2 Project

echo "Setting up Git repository..."

# Note: Git user configuration skipped - using passkey authentication
echo "Note: Git user configuration skipped (using passkey authentication)"

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: ICMP C2 Project with full and low-privilege modes"

echo "Git repository setup complete!"
echo "Current status:"
git status

echo ""
echo "To add a remote repository, use:"
echo "git remote add origin https://github.com/SweetLikeTwinkie/ICMP-C2.git"
echo "git push -u origin master"
echo ""
echo "For GitHub with passkey authentication:"
echo "1. Create a new repository on GitHub"
echo "2. Copy the repository URL"
echo "3. Run: git remote add origin <your-repo-url>"
echo "4. Run: git push -u origin master" 