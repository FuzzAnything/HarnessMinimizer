#!/usr/bin/env python3
"""Collect the replay evaluation."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from harnessreducer.evaluation_cli import collect_evaluation

if __name__ == "__main__":
    raise SystemExit(collect_evaluation("replay"))
