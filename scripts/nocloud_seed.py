#!/usr/bin/env python3
"""Write the tiny ISO9660 seed disk understood by cloud-init's NoCloud source.

The runner needs a local seed because a locked-down guest cannot fetch its
cloud-init config over the network before the config itself can reset UFW.
"""
from pathlib import Path

SECTOR_SIZE = 2048
PVD_SECTOR = 16
ROOT_SECTOR = 20


def _both_endian(value: int, size: int) -> bytes:
    return value.to_bytes(size, 'little') + value.to_bytes(size, 'big')


def _directory_record(name: bytes, extent: int, size: int, *, directory=False) -> bytes:
    record_length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(record_length)
    record[0] = record_length
    record[2:10] = _both_endian(extent, 4)
    record[10:18] = _both_endian(size, 4)
    # Fixed, valid ISO9660 timestamp: 2026-10-25 00:00:00 UTC.
    record[18:25] = bytes((126, 10, 25, 0, 0, 0, 0))
    record[25] = 0x02 if directory else 0
    record[28:32] = _both_endian(1, 2)
    record[32] = len(name)
    record[33:33 + len(name)] = name
    return bytes(record)


def _path_table(root_sector: int, *, big_endian: bool) -> bytes:
    endian = 'big' if big_endian else 'little'
    # The root entry has a one-byte identifier (0), padded to an even size.
    return (bytes((1, 0)) + root_sector.to_bytes(4, endian) +
            (1).to_bytes(2, endian) + b'\x00\x00')


def write_seed_iso(path: Path, user_data: str, instance_id: str) -> Path:
    """Create a read-only NoCloud seed ISO containing user-data and meta-data."""
    if not instance_id or any(char in instance_id for char in '\r\n\x00'):
        raise ValueError('instance_id must be a non-empty single-line value')
    user_bytes = user_data.encode('utf-8')
    meta_bytes = (f'instance-id: {instance_id}\nlocal-hostname: tripwire\n'
                  .encode('ascii'))
    file_records = []
    data_entries = []
    next_sector = ROOT_SECTOR + 1
    for name, content in ((b'USER-DATA;1', user_bytes),
                          (b'META-DATA;1', meta_bytes)):
        data_entries.append((name, content, next_sector))
        file_records.append(_directory_record(name, next_sector, len(content)))
        next_sector += (len(content) + SECTOR_SIZE - 1) // SECTOR_SIZE
    root_size = 2 * 34 + sum(len(record) for record in file_records)
    root_data = b''.join((
        _directory_record(b'\x00', ROOT_SECTOR, root_size, directory=True),
        _directory_record(b'\x01', ROOT_SECTOR, root_size, directory=True),
        *file_records,
    ))
    root_sectors = (len(root_data) + SECTOR_SIZE - 1) // SECTOR_SIZE
    if root_sectors != 1:
        raise ValueError('NoCloud seed directory unexpectedly spans multiple sectors')

    path_table_size = len(_path_table(ROOT_SECTOR, big_endian=False))
    # ISO9660 media must be at least 300 logical blocks for standard readers.
    volume_sectors = max(next_sector, ROOT_SECTOR + root_sectors + 1, 300)
    image = bytearray(volume_sectors * SECTOR_SIZE)

    pvd = memoryview(image)[PVD_SECTOR * SECTOR_SIZE:(PVD_SECTOR + 1) * SECTOR_SIZE]
    pvd[0:7] = b'\x01CD001\x01'
    pvd[8:40] = b'TRIPWIRE'.ljust(32, b' ')
    pvd[40:72] = b'CIDATA'.ljust(32, b' ')
    pvd[80:88] = _both_endian(volume_sectors, 4)
    pvd[120:124] = _both_endian(1, 2)
    pvd[124:128] = _both_endian(1, 2)
    pvd[128:132] = _both_endian(SECTOR_SIZE, 2)
    pvd[132:140] = _both_endian(path_table_size, 4)
    pvd[140:144] = (18).to_bytes(4, 'little')
    pvd[148:152] = (19).to_bytes(4, 'big')
    pvd[156:190] = _directory_record(b'\x00', ROOT_SECTOR,
                                      len(root_data), directory=True)
    pvd[881] = 1
    image[17 * SECTOR_SIZE] = 255
    image[17 * SECTOR_SIZE + 1:17 * SECTOR_SIZE + 7] = b'CD001\x01'
    image[18 * SECTOR_SIZE:18 * SECTOR_SIZE + path_table_size] = _path_table(
        ROOT_SECTOR, big_endian=False)
    image[19 * SECTOR_SIZE:19 * SECTOR_SIZE + path_table_size] = _path_table(
        ROOT_SECTOR, big_endian=True)
    image[ROOT_SECTOR * SECTOR_SIZE:ROOT_SECTOR * SECTOR_SIZE + len(root_data)] = root_data
    for _, content, extent in data_entries:
        start = extent * SECTOR_SIZE
        image[start:start + len(content)] = content

    path = Path(path)
    path.write_bytes(image)
    return path
