"""Allows running the tool as: python3 -m securityaudit"""
import sys
from securityaudit.cli import main

if __name__ == "__main__":
    sys.exit(main())
