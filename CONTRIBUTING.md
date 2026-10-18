Contributing
============

Thanks for considering contributing!

Running tests
-------------

This project is a small Python package. You can run tests in two ways:

- From a checkout without installing the package:

  PYTHONPATH=src python -m unittest discover -s tests -v

- Install locally and run with pytest (recommended for CI parity):

  python -m pip install --upgrade pip
  python -m pip install .
  pytest

Reporting issues
----------------

Please open an issue with a minimal reproduction and the output of `python -V`.
