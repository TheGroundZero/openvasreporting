#!/bin/bash
python3.7 setup.py sdist bdist_wheel
twine upload dist/*
