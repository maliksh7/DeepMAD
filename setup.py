'''
This file is run by pip to install the package. It can also be run
on its own using the command:

    python setup.py sdist bdist_wheel

python - run the following file as a python script
setup.py - the file to run
sdist - make a source distribution (typically in a gzip or tar file)
bdist_wheel - make a binary distribution (a .whl file)

You may use either option or both; it will each version specified
and place them in the 'dist' folder.
'''

import setuptools

# Adds the 'readme.md' file as the long description
# to be added to the metadata below.
with open("README.md", "r") as fh:
    long_description = fh.read()

# This brings the contents of the requirements.txt file
# in and stores it in 'dependencies'
with open("requirements.txt", "rt", encoding='utf-16') as fl:
    dependencies = [line for line in fl.readlines()]

setuptools.setup(
    name="prc-flowmeter",
    version="0.2.0",
    author="Stephen Wight",
    author_email="swight@prc-hsv.com",
    description="A tool for deriving statistical features from pcap data.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/prc-hsv/flowmeter",
    packages=setuptools.find_packages(),
    install_requires=dependencies,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6'
)
