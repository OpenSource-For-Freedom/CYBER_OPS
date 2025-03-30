from setuptools import setup, find_packages

setup(
    name="hardn",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "tkinter",  # GUI that's huge 
        "requests", #  requests... 
        "lynis",    # thanks to kiukcat :)
    ],
    entry_points={
        "console_scripts": [
            "hardn=hardn.hardn:main",
        ],
    },
    author="Tim 'Tank' Burns", #me 
    description="HARDN - The Linux Security Project",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_GITHUB_USERNAME/HARDN",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
)