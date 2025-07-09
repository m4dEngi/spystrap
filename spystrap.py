import zipfile
import os
import glob
import io
import stat
import zlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Self
from dataclasses import dataclass
from zipfile import ZipFile
from vlzma import vlzma
from enum import Enum, Flag
import vdf
import aiohttp
import asyncio
import hashlib
import re
from ostype import EOSType
import argparse


CS_CHUNK_SIZE = 65536
DL_CHUNK_SIZE = 16384


CLIENT_PLATFORM = "ubuntu12"
CLIENT_DL_BASE = "https://client-update.steamstatic.com/"


PACKAGE_NAME_RE = re.compile(r'^(.+?)\.(zip(?:\.vz)?)\.([a-fA-F0-9]{40})(?:_(\d+))?$')


class FileStatus(Enum):
    INVALID = -1
    OK = 1
    MISSING = 2
    CHECKSUM_MISMATCH = 4
    SIZE_MISMATCH = 8


class FileType(Flag):
    INVALID = 0
    FILE = 1
    DIRECTORY = 2
    SYMLINK = 4
    EXECUTABLE = 8
    OTHER = 16


class PackageType(Enum):
    ZIP_VZ = 0
    ZIP = 1


@dataclass
class PackagedFile:
    name: str
    size: int
    crc32: int
    timestamp: int
    file_type: FileType


@dataclass
class SteamPackageInfo:
    file: str
    size: int
    sha2: str
    vz: str
    sha2_vz: str
    is_bootstrapper_package: bool = False


# fix_slashes helper for zip packed files
# for directories and other wierd paths
def fix_slashes(file_path: str) -> str:
    return file_path.replace("/", os.path.sep).replace("\\", os.path.sep)


def unfix_slashes(file_path: str) -> str:
    return file_path.replace("/", "\\")


# few checksum helpers
def get_file_crc32(path: str) -> int:
    with open(path, "rb") as file:
        crc32 = 0
        chunks = int(os.stat(path).st_size / CS_CHUNK_SIZE) + 1
        for chunk in range(chunks):
            crc32 = zlib.crc32(file.read(CS_CHUNK_SIZE), crc32)
        return crc32


def get_file_sha2(path: str) -> str:
    sha2 = hashlib.sha256()
    with open(path, "rb") as file:
        chunks = int(os.stat(path).st_size / CS_CHUNK_SIZE) + 1
        for chunk in range(chunks):
            sha2.update(file.read(CS_CHUNK_SIZE))
    return sha2.hexdigest()


def get_file_sha1(path: str) -> str:
    sha1 = hashlib.sha1()
    with open(path, "rb") as file:
        chunks = int(os.stat(path).st_size / CS_CHUNK_SIZE) + 1
        for chunk in range(chunks):
            sha1.update(file.read(CS_CHUNK_SIZE))
    return sha1.hexdigest()


class InstalledManifest:
    def __init__(self, installed_path: str):
        self.path = installed_path
        self.files: Dict[str, PackagedFile] = {}
        self.version: int = 3
        self.os_ver: int = int(EOSType.Linux6x.value)
        self.sha1: Optional[str] = None
        self.is_valid: bool = False

    def _validate(self) -> FileStatus:
        if not os.path.exists(self.path):
            return FileStatus.MISSING
        with open(self.path, "r") as f:
            lines = f.readlines()
            if len(lines) < 3:
                return FileStatus.SIZE_MISMATCH
            sha = hashlib.sha1("".join(lines[:-1]).encode()).digest().hex()
            if sha.upper() != lines[-1][5:].strip():
                return FileStatus.CHECKSUM_MISMATCH
        return FileStatus.OK

    def open(self) -> bool:
        if self._validate() != FileStatus.OK:
            return False

        self.is_valid = True

        with open(self.path, "r") as installed:
            for line in installed:
                if line.find("=") == -1:
                    path_size, timestamp, crc = line.split(";")
                    path, size = path_size.split(",")
                    if size == "-1":
                        file_type = FileType.DIRECTORY
                    elif size == "-2":
                        file_type = FileType.SYMLINK
                    else:
                        file_type = FileType.FILE
                    self.files[path] = PackagedFile(path, int(size), int(crc), int(timestamp), file_type)
                else:
                    if line.startswith("OSVER="):
                        self.os_ver = int(line[6:])
                    elif line.startswith("VERSION="):
                        self.version = int(line[8:])
                    elif line.startswith("SHA1="):
                        self.sha1 = line[5:].strip()
        return True

    def close(self) -> None:
        pass

    def write(self, out_path: str = None) -> None:
        if not self.files:
            return

        out_path = out_path if out_path else self.path
        with open(out_path, "w") as out:
            lines = []
            for file_name, ex_info in self.files.items():
                file_size = ex_info.size
                if ex_info.file_type & FileType.SYMLINK == FileType.SYMLINK:
                    file_size = -2
                elif ex_info.file_type & FileType.DIRECTORY == FileType.DIRECTORY:
                    file_size = -1
                lines.append(f"{fix_slashes(ex_info.name)},{file_size};{ex_info.timestamp};{ex_info.crc32}")
            lines.append(f"OSVER={self.os_ver}")
            lines.append(f"VERSION={self.version}\n")
            manifest = "\n".join(lines)
            sha = hashlib.sha1(manifest.encode()).digest().hex()
            out.write(manifest)
            out.write(f"SHA1={sha.upper()}\n")


class SteamPackage:
    def __init__(self, package_path: str):
        self.path = package_path
        self._package: Optional[ZipFile] = None
        self.package_type: PackageType = PackageType.ZIP_VZ
        self.files: List[PackagedFile] = []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return self

    def _file_type(self, zf: zipfile.ZipInfo) -> FileType:
        if zf.is_dir():
            return FileType.DIRECTORY

        unix_attrs = zf.external_attr >> 16
        ft = FileType.FILE
        if unix_attrs & stat.S_IXUSR == stat.S_IXUSR \
            or unix_attrs & stat.S_IXGRP == stat.S_IXGRP \
            or unix_attrs & stat.S_IXOTH == stat.S_IXOTH:
            ft |= FileType.EXECUTABLE
        if unix_attrs & stat.S_IFLNK == stat.S_IFLNK:
            ft |= FileType.SYMLINK
        return ft

    def _read_contents(self) -> None:
        if self._package:
            for file in self._package.filelist:
                self.files.append(PackagedFile(fix_slashes(file.filename),
                                               int(file.file_size),
                                               int(file.CRC),
                                               int(datetime(*file.date_time).timestamp()),
                                               self._file_type(file)))

    def open(self) -> bool:
        if self._package:
            return True

        try:
            if self.path.find(".zip.vz") != -1:
                self._package = ZipFile(io.BytesIO(vlzma.decompress(self.path)))
            else:
                self.package_type = PackageType.ZIP
                self._package = ZipFile(self.path, "r")
        except ValueError:
            return False
        except:
            return False

        self._read_contents()
        return True

    def close(self) -> None:
        if self._package:
            self._package.close()
            self._package = None

    def extract_file(self, file: PackagedFile, out_path: str) -> bool:
        p_out = os.path.join(out_path, fix_slashes(file.name))
        if file.file_type & FileType.DIRECTORY:
            os.makedirs(p_out, exist_ok=True)
        elif file.file_type & FileType.SYMLINK:
            os.makedirs(os.path.dirname(p_out), exist_ok=True)
            try:
                if os.path.exists(p_out):
                    os.unlink(p_out)
                os.symlink(self._package.read(unfix_slashes(file.name)).decode(encoding="utf-8"), p_out)
            except Exception as ex:
                return False
        else:
            self._package.extract(file.name, out_path)

        if file.file_type & FileType.EXECUTABLE:
            if os.path.exists(p_out):
                os.chmod(p_out, os.stat(p_out).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        return True

    def extract_all(self, out_path: str) -> None:
        for file in self.files:
            self.extract_file(file, out_path)


class UpdateManifest:
    def __init__(self):
        self.platform: Optional[str] = None
        self.packages: Dict[str, SteamPackageInfo] = {}
        self.version: int = -1

    def try_parse(self, manifest: str, client_platform: str) -> bool:
        try:
            m_vdf = vdf.loads(manifest)[client_platform]
            self.platform = client_platform
            self.version = int(m_vdf["version"])
            del m_vdf["version"]
            for key, value in m_vdf.items():
                self.packages[key] = SteamPackageInfo(fix_slashes(value["file"]),
                                                      int(value["size"]),
                                                      value["sha2"],
                                                      value.get("zipvz", None),
                                                      value.get("sha2vz", None),
                                                      bool(value.get("IsBootstrapperPackage", False)))
            return True
        except Exception as ex:
            pass
        return False


def find_local_packages(packages_path: str) -> Dict[str, SteamPackageInfo]:
    packages = {}
    if os.path.exists(packages_path):
        local_packages_paths = glob.glob(os.path.join(packages_path, "*.zip.*"))

        for package in local_packages_paths:
            f_name = package.split(os.path.sep)[-1]
            match = PACKAGE_NAME_RE.match(f_name)
            if match:
                package_name, zvz, sha1sum, size = match.groups()
                if zvz == "zip.vz":
                    packages[package_name] = SteamPackageInfo("", int(size), "", f_name, "")
                elif zvz == "zip":
                    packages[package_name] = SteamPackageInfo(f_name, os.stat(package).st_size, "", "", "")
    return packages


async def get_remote_text(manifest_url: str) -> Optional[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{manifest_url}?{int(datetime.now(tz=timezone.utc).timestamp())}") as response:
                if response.status == aiohttp.http.HTTPStatus.OK:
                    return await response.text()
    except Exception as ex:
        pass
    return None


async def download_file(file_url: str, out_path: str) -> bool:
    try:
        temp_name = out_path + "_"
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        async with aiohttp.ClientSession() as session:
            async with session.get(file_url) as response:
                with open(temp_name, "wb") as f_out:
                    async for chunk in response.content.iter_chunked(DL_CHUNK_SIZE):
                        f_out.write(chunk)
                if os.path.exists(out_path):
                    os.unlink(out_path)
                os.rename(temp_name, out_path)
                return True
    except Exception as ex:
        return False


def validate_installed(install_path: str, installed_files: Dict[str, PackagedFile]) -> Dict[str, PackagedFile]:
    broken_files = {}
    for path, file in installed_files.items():
        file_path = f"{install_path}/{file.name}"
        if not os.path.exists(file_path):
            broken_files[path] = file
        else:
            if file.file_type == FileType.FILE:
                if os.stat(file_path).st_size != file.size or get_file_crc32(file_path) != file.crc32:
                    broken_files[path] = file
    return broken_files


def validate_packages(packages_path: str, packages: Dict[str, SteamPackageInfo] = None) -> Dict[str, SteamPackageInfo]:
    broken_packages = {}
    for name, package in packages.items():
        file, sha2 = (package.file, package.sha2) if not package.vz else (package.vz, package.sha2_vz)
        package_file = os.path.join(packages_path, file)
        if os.path.exists(package_file):
            if get_file_sha2(package_file) != sha2:
                broken_packages.setdefault(name, package)
        else:
            broken_packages.setdefault(name, package)
    return broken_packages


def cleanup(packages_path: str):
    # remove temp files
    temp_files = glob.glob(f"{packages_path}/*_")
    for file in temp_files:
        if os.path.isdir(file):
            os.rmdir(file)
        else:
            os.unlink(file)


async def update(install_path: str, platform: str, client_type: str = ""):
    packages_path = os.path.join(install_path, "package")
    manifest_name = "steam_client_" + platform
    os.makedirs(install_path, exist_ok=True)
    os.makedirs(packages_path, exist_ok=True)

    local_manifest_path = os.path.join(packages_path, f"{manifest_name}.manifest")
    local_manifest = UpdateManifest()
    broken_packages = {}
    if os.path.exists(local_manifest_path):
        with open(local_manifest_path, "r") as m:
            if local_manifest.try_parse(m.read(), platform):
                broken_packages = validate_packages(packages_path, local_manifest.packages)

    for broken, meta in broken_packages.items():
        dl_file = meta.file if not meta.vz else meta.vz
        if await download_file(f"{CLIENT_DL_BASE}/{dl_file}", os.path.join(packages_path,dl_file)):
            del broken_packages[broken]

    installed_manifest_path = os.path.join(packages_path, f"{manifest_name}.installed")
    local_install = InstalledManifest(installed_manifest_path)
    broken_files = {}
    if local_install.open():
        broken_files = validate_installed(install_path, local_install.files)

    fixed_list = []
    if broken_files:
        if not broken_packages and local_manifest.version != -1:
            for package_name, package_info in local_manifest.packages.items():
                package_path = package_info.file if not package_info.vz else package_info.vz
                package = SteamPackage(os.path.join(packages_path, package_path))
                if package.open():
                    for broken, ex_info in broken_files.items():
                        found = [file for file in package.files if file.name == broken]
                        if found:
                            if package.extract_file(found[0], install_path):
                                fixed_list.append(broken)
                if not broken_files:
                    break
    for fixed in fixed_list:
        del broken_files[fixed]
    fixed_list.clear()

    package_dl_que: Dict[str, SteamPackageInfo] = {}
    local_packages = find_local_packages(packages_path)
    remote_manifest_text = await get_remote_text(f"{CLIENT_DL_BASE}/{manifest_name}")
    if remote_manifest_text:
        remote_manifest = UpdateManifest()
        if remote_manifest.try_parse(remote_manifest_text, CLIENT_PLATFORM):
            if remote_manifest.version > local_manifest.version:
                for package_name, package_meta in remote_manifest.packages.items():
                    dl_file, sha2 = (package_meta.file, package_meta.sha2) if not package_meta.vz else (package_meta.vz, package_meta.sha2_vz)
                    if package_name in local_manifest.packages:
                        dl_file_local, sha2_local = (package_meta.file, package_meta.sha2) if not package_meta.vz else (
                            package_meta.vz, package_meta.sha2_vz)
                        if sha2_local != sha2:
                            package_dl_que[package_name] = package_meta
                    else:
                        local_dl_name = os.path.join(packages_path, dl_file)
                        if os.path.exists(local_dl_name):
                            test_sha2 = get_file_sha2(local_dl_name)
                            if test_sha2 != sha2:
                                package_dl_que[package_name] = package_meta
                        else:
                            package_dl_que[package_name] = package_meta

    update_ok = True
    os.makedirs(os.path.join(packages_path, "tmp_"), exist_ok=True)
    for package_name, package_info in package_dl_que.items():
        dl_file = package_info.file if not package_info.vz else package_info.vz
        dl_out_t = os.path.join(packages_path, "tmp_",  dl_file)
        dl_out = os.path.join(packages_path, dl_file)
        print(f"Downloading {package_name} ... ", end="")
        if await download_file(f"{CLIENT_DL_BASE}/{dl_file}", dl_out_t):
            print(" OK")
            if package_name in local_packages:
                file_name = local_packages[package_name].file if not local_packages[package_name].vz else local_packages[package_name].vz
                os.unlink(os.path.join(packages_path, file_name))
            os.rename(dl_out_t, dl_out)
        else:
            update_ok = False
            print(" FIAL")

    if update_ok:
        with open(local_manifest_path, "w") as f:
            f.writelines(remote_manifest_text)

    if not local_install.is_valid:
        local_install_new = InstalledManifest(installed_manifest_path)
        update_manifest = UpdateManifest()
        if update_manifest.try_parse(open(local_manifest_path, "r").read(), CLIENT_PLATFORM):
            for name, package in update_manifest.packages.items():
                package_path = package.file if not package.vz else package.vz
                steam_package = SteamPackage(os.path.join(packages_path,package_path))
                if steam_package.open():
                    steam_package.extract_all(install_path)
                    for file in steam_package.files:
                        local_install_new.files[file.name] = file
        local_install_new.write()
    else:
        for name, package in package_dl_que.items():
            package_path = package.file if not package.vz else package.vz
            steam_package = SteamPackage(os.path.join(packages_path, package_path))
            if steam_package.open():
                steam_package.extract_all(install_path)
                for file in steam_package.files:
                    local_install.files[file.name] = file
        local_install.write()

    cleanup(packages_path)


async def main(steam_install_dir: str, client_platform: str):
    await update(steam_install_dir, client_platform)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="SPyStrap", description="Half-assed steam client updater updater")
    parser.add_argument("-i", "--install_path", help="steam install path", type=str, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.install_path, CLIENT_PLATFORM))
