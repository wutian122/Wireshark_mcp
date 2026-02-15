import sys
import os

# Add the project root to the python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wireshark_mcp.server import main

if __name__ == "__main__":
    main()
