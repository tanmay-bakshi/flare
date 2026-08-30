"""Dependency-free drift checks for checked-in conformance corpora."""

from std.pathlib import Path


comptime _FNV_OFFSET: UInt64 = UInt64(14695981039346656037)
comptime _FNV_PRIME: UInt64 = UInt64(1099511628211)


@fieldwise_init
struct CorpusSnapshot(Copyable, Movable):
    """Raw corpus shape used to keep typed fixtures synchronized.

    :ivar json_file_count: Number of ``*.json`` files in the directory.
    :ivar fingerprint: FNV-1a over ordered filenames and raw file contents.
    """

    var json_file_count: Int
    var fingerprint: UInt64


def _update_fingerprint(fingerprint: UInt64, bytes: Span[UInt8, _]) -> UInt64:
    var updated = fingerprint
    for index in range(len(bytes)):
        updated = (updated ^ UInt64(bytes[index])) * _FNV_PRIME
    return updated


def _update_separator(fingerprint: UInt64) -> UInt64:
    return (fingerprint ^ UInt64(0)) * _FNV_PRIME


def snapshot_corpus(
    directory: String, filenames: List[String]
) raises -> CorpusSnapshot:
    """Fingerprint explicitly ordered files and count the directory corpus.

    :param directory: Repo-relative corpus directory.
    :param filenames: Canonically ordered JSON filenames mirrored by the test.
    :returns: The directory's raw count and stable content fingerprint.
    """
    var root = Path(directory)
    var json_file_count = 0
    var entries = root.listdir()
    for index in range(len(entries)):
        if String(entries[index]).endswith(".json"):
            json_file_count += 1

    var fingerprint = _FNV_OFFSET
    for index in range(len(filenames)):
        var filename = filenames[index]
        fingerprint = _update_fingerprint(fingerprint, filename.as_bytes())
        fingerprint = _update_separator(fingerprint)
        var contents = (root / filename).read_text()
        fingerprint = _update_fingerprint(fingerprint, contents.as_bytes())
        fingerprint = _update_separator(fingerprint)

    return CorpusSnapshot(
        json_file_count=json_file_count, fingerprint=fingerprint
    )
