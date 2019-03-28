import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="camect-py",
    version="0.1.1",
    author="Chao Liu",
    author_email="chao@camect.com",
    description="A client library to talk to Camect.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/camect/camect-py",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
