from setuptools import setup, find_packages
# still need to fix file path to update new file name

setup(
    name="hardn",  
    version="1.4.0",
    author="Tim 'TANK' Burns", #me
    author_email="support@grdv.org",
    description="A Linux security hardening automation tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/OpenSource-For-Freedom/Linux",
    packages=find_packages(),
    install_requires=[
        "tk", "setuptools", "wheel"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security", # never less
    ],
    entry_points={
        "console_scripts": [
            "hardn=hardn.hardn:main",
        ],
    },
    python_requires=">=3.8",
)
