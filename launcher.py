"""PyInstaller belépési pont – a helyi (asztali) domain-recon."""
import multiprocessing
import sys

from app.desktop import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
