#!/usr/bin/env python3
"""Run the replay evaluation."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from harnessreducer.evaluation_cli import run_evaluation

if __name__ == "__main__":
    raise SystemExit(run_evaluation("replay"))
