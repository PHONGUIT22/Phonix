"""Response Rehydrator for Phonix v2.0 Enterprise Compliance Gateway.

Restores redacted placeholders (e.g. <REDACTED_SECRET_01>) in LLM completion responses
back to their original literal values using the ephemeral request vault.
"""

from __future__ import annotations

import re
from typing import AsyncIterable, AsyncIterator, Iterable, Iterator


class Rehydrator:
    """Restores sensitive literals in model output before delivery to client application.

    Ensures seamless developer experience by transparently replacing redaction
    tokens with the authentic secrets known only to the enterprise boundary.
    """

    PLACEHOLDER_PATTERN: re.Pattern[str] = re.compile(r"<REDACTED_[A-Z0-9_]+>")

    def rehydrate(self, text: str, vault: dict[str, str]) -> str:
        """Replaces all matched placeholders in text with values from the ephemeral vault.

        Args:
            text: Raw model completion containing redacted tokens.
            vault: Ephemeral mapping {placeholder: original_secret}.

        Returns:
            Fully restored response text.
        """
        if not vault or not text:
            return text

        rehydrated = text
        for placeholder, original in vault.items():
            rehydrated = rehydrated.replace(placeholder, original)

        return rehydrated

    def stream_rehydrate(
        self, chunks: Iterable[str], vault: dict[str, str]
    ) -> Iterator[str]:
        """Rehydrates placeholders across a synchronous stream of text chunks.

        Buffers only partial '<REDACTED_...' tags across chunk boundaries and flushes
        non-tag text immediately to preserve zero-latency streaming.
        """
        if not vault:
            for chunk in chunks:
                if chunk:
                    yield chunk
            return

        max_tag_len = max([len(k) for k in vault.keys()], default=36) + 4
        buffer = ""

        for chunk in chunks:
            if not chunk:
                continue
            buffer += chunk

            while buffer:
                start_idx = buffer.find("<")
                if start_idx == -1:
                    # No potential tag opening in buffer, flush all
                    yield buffer
                    buffer = ""
                    break

                if start_idx > 0:
                    # Flush characters before the '<'
                    yield buffer[:start_idx]
                    buffer = buffer[start_idx:]

                # Now buffer starts with '<'
                end_idx = buffer.find(">")
                if end_idx != -1:
                    tag = buffer[: end_idx + 1]
                    yield vault.get(tag, tag)
                    buffer = buffer[end_idx + 1 :]
                else:
                    # No closing '>' yet. Check if buffer has exceeded valid tag length or contains whitespace
                    if len(buffer) > max_tag_len or any(
                        c in buffer for c in (" ", "\n", "\t", "\r", '"', "'", ";", "{", "}")
                    ):
                        yield buffer[0]
                        buffer = buffer[1:]
                    else:
                        # Wait for next chunk to complete potential tag
                        break

        if buffer:
            yield self.rehydrate(buffer, vault)

    async def astream_rehydrate(
        self, chunks: AsyncIterable[str], vault: dict[str, str]
    ) -> AsyncIterator[str]:
        """Rehydrates placeholders across an asynchronous stream of text chunks."""
        if not vault:
            async for chunk in chunks:
                if chunk:
                    yield chunk
            return

        max_tag_len = max([len(k) for k in vault.keys()], default=36) + 4
        buffer = ""

        async for chunk in chunks:
            if not chunk:
                continue
            buffer += chunk

            while buffer:
                start_idx = buffer.find("<")
                if start_idx == -1:
                    yield buffer
                    buffer = ""
                    break

                if start_idx > 0:
                    yield buffer[:start_idx]
                    buffer = buffer[start_idx:]

                end_idx = buffer.find(">")
                if end_idx != -1:
                    tag = buffer[: end_idx + 1]
                    yield vault.get(tag, tag)
                    buffer = buffer[end_idx + 1 :]
                else:
                    if len(buffer) > max_tag_len or any(
                        c in buffer for c in (" ", "\n", "\t", "\r", '"', "'", ";", "{", "}")
                    ):
                        yield buffer[0]
                        buffer = buffer[1:]
                    else:
                        break

        if buffer:
            yield self.rehydrate(buffer, vault)

    def find_unmapped_placeholders(self, text: str, vault: dict[str, str]) -> list[str]:
        """Identifies any redaction placeholders in text that are missing from vault."""
        matches = self.PLACEHOLDER_PATTERN.findall(text)
        return [m for m in matches if m not in vault]
