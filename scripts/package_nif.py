#!/usr/bin/env python3

import gzip
import pathlib
import sys
import tarfile


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: package_nif.py SOURCE ARCHIVE_NAME")

    source = pathlib.Path(sys.argv[1])
    archive_name = pathlib.Path(sys.argv[2])

    if not source.is_file():
        raise SystemExit(f"native library does not exist: {source}")

    data = source.read_bytes()
    member = tarfile.TarInfo(archive_name.name.removesuffix(".tar.gz"))
    member.size = len(data)
    member.mode = 0o755
    member.mtime = 0
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""

    with archive_name.open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                archive.addfile(member, fileobj=BytesReader(data))


class BytesReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.data) - self.offset

        chunk = self.data[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


if __name__ == "__main__":
    main()
