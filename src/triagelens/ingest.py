"""Bounded streaming JSONL ingestion (P1-02, P3-02)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Iterator

from triagelens.config import RunConfig

_DRAIN_CHUNK_SIZE = 64 * 1024


class IngestionLimitError(RuntimeError):
    """Raised when an input file violates global batch resource limits."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class RawIngestedLine:
    """A single indexed line read from the input stream with bounded memory."""

    record_index: int
    raw_bytes: bytes
    line_sha256: str
    is_oversized: bool


class BoundedJsonlReader:
    """Streams JSONL lines with strict byte and record count limits before parsing."""

    def __init__(self, input_path: str | Path, config: RunConfig) -> None:
        self.input_path = Path(input_path)
        self.config = config
        self._file_hasher = hashlib.sha256()
        self.records_read = 0
        self.bytes_read = 0

    @property
    def input_file_sha256(self) -> str:
        return self._file_hasher.hexdigest()

    def validate_source_file(self) -> None:
        """Check file existence, regular-file status, and total byte limit before reading."""
        if not self.input_path.exists():
            raise IngestionLimitError("input_not_found", "Specified input file does not exist")
        if self.input_path.is_dir():
            raise IngestionLimitError("input_is_directory", "Specified input path is a directory")
        try:
            st = os.stat(self.input_path, follow_symlinks=True)
        except OSError as exc:
            raise IngestionLimitError("input_stat_failed", "Unable to inspect input file metadata") from exc

        if st.st_size > self.config.max_input_file_bytes:
            raise IngestionLimitError(
                "input_file_too_large",
                f"Input file size ({st.st_size} bytes) exceeds limit of {self.config.max_input_file_bytes} bytes",
            )

    def __iter__(self) -> Iterator[RawIngestedLine]:
        self.validate_source_file()
        max_line = self.config.max_record_bytes

        with open(self.input_path, "rb") as fh:
            record_index = 0
            while True:
                chunk = fh.readline(max_line + 1)
                if not chunk:
                    break

                record_index += 1
                if record_index > self.config.max_records_per_run:
                    raise IngestionLimitError(
                        "too_many_records",
                        f"Input exceeds maximum record count of {self.config.max_records_per_run}",
                    )

                line_hasher = hashlib.sha256()
                line_hasher.update(chunk)
                self._file_hasher.update(chunk)
                self.bytes_read += len(chunk)

                if self.bytes_read > self.config.max_input_file_bytes:
                    raise IngestionLimitError(
                        "input_file_too_large",
                        f"Streamed bytes exceed limit of {self.config.max_input_file_bytes} bytes",
                    )

                # Check if the line exceeded max_record_bytes without hitting a newline
                if len(chunk) > max_line and not chunk.endswith(b"\n"):
                    while True:
                        drain = fh.read(_DRAIN_CHUNK_SIZE)
                        if not drain:
                            break
                        nl_pos = drain.find(b"\n")
                        if nl_pos != -1:
                            consumed = drain[: nl_pos + 1]
                            line_hasher.update(consumed)
                            self._file_hasher.update(consumed)
                            self.bytes_read += len(consumed)
                            # Seek back the remainder after the newline
                            remainder_len = len(drain) - (nl_pos + 1)
                            if remainder_len > 0:
                                fh.seek(-remainder_len, os.SEEK_CUR)
                            break
                        line_hasher.update(drain)
                        self._file_hasher.update(drain)
                        self.bytes_read += len(drain)
                        if self.bytes_read > self.config.max_input_file_bytes:
                            raise IngestionLimitError(
                                "input_file_too_large",
                                f"Streamed bytes exceed limit of {self.config.max_input_file_bytes} bytes",
                            )
                    self.records_read = record_index
                    yield RawIngestedLine(
                        record_index=record_index,
                        raw_bytes=b"",
                        line_sha256=line_hasher.hexdigest(),
                        is_oversized=True,
                    )
                    continue

                stripped = chunk.rstrip(b"\r\n")
                is_oversized = len(stripped) > max_line
                self.records_read = record_index
                yield RawIngestedLine(
                    record_index=record_index,
                    raw_bytes=b"" if is_oversized else stripped,
                    line_sha256=line_hasher.hexdigest(),
                    is_oversized=is_oversized,
                )
