from setuptools import setup, find_packages

setup(
    name="rpi-master-service",
    version="0.1.0",
    packages=find_packages(),
    package_dir={"": "src"},
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "rpi-master=main:main",
        ],
    },
)