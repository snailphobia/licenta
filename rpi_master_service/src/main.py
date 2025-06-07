#!/usr/bin/env python3
"""Main entry point for the RPI Master Service."""

import sys
import os

# Add src directory to path when running from root
if __name__ == "__main__":
    # Get the directory containing this script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Add parent directory (src) to Python path
    sys.path.insert(0, os.path.dirname(current_dir))

def main():
    """Main application function."""
    print("RPI Master Service starting...")
    # Your application logic here

if __name__ == "__main__":
    main()