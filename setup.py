from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dockerfile-guard",
    version="0.1.0",
    author="slopggobblercobbler81",
    author_email="slopggobblercobbler81@users.noreply.github.com",
    description="Fast static analyzer and optimization advisor for Dockerfiles detecting security risks, cache bloat, and best practice violations.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/slopggobblercobbler81/dockerfile-guard",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "dockerfile-guard=dockerfile_guard.cli:main",
        ],
    },
)
