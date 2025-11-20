"""
Very basic smoke test to ensure the GuardDog package imports and main() runs.
"""

from guarddog.main import main

def test_main_runs():
    # For now we just assert that main() returns an int and does not crash.
    code = main()
    assert isinstance(code, int)
