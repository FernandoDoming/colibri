from setuptools import setup

setup(
    name="colibri",
    version="0.1.0",
    description="Lightweight malware sandbox",
    url="https://github.com/FernandoDoming/identikit",
    author="Fernando Domínguez",
    author_email="fernando.dom.del@gmail.com",
    license="GNU GPL v3",
    packages=[
        "colibri",
        "colibri.syscalls",
        "colibri.core",
        "colibri.utils",
    ],
    install_requires=[
        "qiling>=1.4.2",
    ],

    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8"
    ],

    entry_points = {
        "console_scripts": ["colibri=colibri.colibri:main"]
    },

    include_package_data=True,
    package_data={
        "colibri": [
            "banners/*"
        ]
    }
)
