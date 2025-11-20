"""
Module entry point so GuardDog can be run as `python -m guarddog`
or bundled into an EXE later.
"""
from .main import main

if __name__ == "__main__":
    raise SystemExit(main())
