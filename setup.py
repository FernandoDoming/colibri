import os
import glob

from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):

    def run(self):
        install.run(self)
        self.__post_install()

    def __post_install(self):
        for path in [
            [".colibri"],
            [".colibri", "rootfs"],
        ]:
            try:
                os.makedirs(
                    os.path.join(
                        os.path.expanduser("~"), *path
                    )
                )
            except FileExistsError:
                pass

def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

dir = os.path.dirname(__file__)
rootfs_files = package_files("colibri/rootfs")

setup(
    name="colibri",
    version="0.1.0",
    description="Lightweight malware sandbox",
    url="https://github.com/FernandoDoming/colibri",
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
            "banners/*",
        ] + rootfs_files,
    },
    cmdclass={"install": CustomInstall}
)