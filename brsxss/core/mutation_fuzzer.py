#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 20:55:00 UTC
Status: Created

Mutation Fuzzer - Generate payload variations for filter bypass.
Uses successful payloads as seeds and mutates them.
"""

import re
import random
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

from ..utils.logger import Logger

logger = Logger("core.mutation_fuzzer")


class MutationType(Enum):
    """Types of payload mutations"""

    CASE_SWAP = "case_swap"
    WHITESPACE = "whitespace"
    ENCODING = "encoding"
    TAG_VARIATION = "tag_variation"
    ATTRIBUTE_VARIATION = "attribute_variation"
    QUOTE_VARIATION = "quote_variation"
    COMMENT_INJECTION = "comment_injection"
    NULL_BYTE = "null_byte"
    UNICODE = "unicode"
    CONCATENATION = "concatenation"
    NEWLINE = "newline"
    TAB = "tab"


@dataclass
class MutatedPayload:
    """Mutated payload with metadata"""

    original: str
    mutated: str
    mutations_applied: list[MutationType] = field(default_factory=list)
    generation: int = 1

    def __str__(self) -> str:
        return self.mutated


class MutationFuzzer:
    """
    Generate payload mutations for filter bypass.

    Strategy:
    1. Take successful/promising payloads as seeds
    2. Apply various mutations
    3. Test mutated payloads
    4. Use successful mutations as new seeds
    """

    # Alternative tags for XSS
    TAG_ALTERNATIVES = {
        "script": ["SCRIPT", "ScRiPt", "scr\x00ipt", "scrıpt"],
        "img": [
            "IMG",
            "ImG",
            "image",
            "svg",
            "video",
            "audio",
            "source",
            "input",
            "body",
            "iframe",
        ],
        "svg": ["SVG", "SvG", "math", "video"],
        "body": ["BODY", "html", "frameset"],
        "iframe": ["IFRAME", "frame", "object", "embed"],
        "input": ["INPUT", "textarea", "button", "select", "details", "marquee"],
    }

    # Alternative event handlers
    EVENT_ALTERNATIVES = {
        "onerror": [
            "ONERROR",
            "OnErRoR",
            "onerror ",
            "onerror\t",
            "onerror\n",
            "onerror/",
        ],
        "onload": ["ONLOAD", "OnLoAd", "onload ", "onreadystatechange"],
        "onclick": ["ONCLICK", "OnClIcK", "ondblclick", "onmousedown", "onmouseup"],
        "onmouseover": ["ONMOUSEOVER", "onmouseenter", "onmousemove", "onfocus"],
        "onfocus": ["ONFOCUS", "OnFoCuS", "onblur"],
    }

    # Whitespace variations
    WHITESPACE_CHARS = [" ", "\t", "\n", "\r", "\f", "\v", "\x00", "/", "+"]

    # Quote variations
    QUOTE_CHARS = ['"', "'", "`", "", " "]

    def __init__(self, max_mutations_per_payload: int = 10):
        """Initialize mutation fuzzer"""
        self.max_mutations = max_mutations_per_payload
        self.successful_mutations: list[MutatedPayload] = []
        self.mutation_stats: dict[MutationType, int] = {m: 0 for m in MutationType}

        logger.info("Mutation Fuzzer initialized")

    def mutate(
        self,
        payload: str,
        count: int = 10,
        mutations: Optional[list[MutationType]] = None,
    ) -> list[MutatedPayload]:
        """
        Generate mutated versions of a payload.

        Args:
            payload: Original payload to mutate
            count: Number of mutations to generate
            mutations: Specific mutations to apply (None = all)

        Returns:
            list of mutated payloads
        """
        results: list[MutatedPayload] = []

        if mutations is None:
            mutations = list(MutationType)

        mutation_funcs = {
            MutationType.CASE_SWAP: self._mutate_case,
            MutationType.WHITESPACE: self._mutate_whitespace,
            MutationType.ENCODING: self._mutate_encoding,
            MutationType.TAG_VARIATION: self._mutate_tag,
            MutationType.ATTRIBUTE_VARIATION: self._mutate_attribute,
            MutationType.QUOTE_VARIATION: self._mutate_quotes,
            MutationType.COMMENT_INJECTION: self._mutate_comments,
            MutationType.NULL_BYTE: self._mutate_null_bytes,
            MutationType.UNICODE: self._mutate_unicode,
            MutationType.CONCATENATION: self._mutate_concatenation,
            MutationType.NEWLINE: self._mutate_newlines,
            MutationType.TAB: self._mutate_tabs,
        }

        seen = {payload}  # Track unique mutations
        attempts = 0
        max_attempts = count * 5

        while len(results) < count and attempts < max_attempts:
            attempts += 1

            # Pick random mutation type
            mutation_type = random.choice(mutations)
            mutate_func = mutation_funcs.get(mutation_type)

            if not mutate_func:
                continue

            try:
                mutated = mutate_func(payload)

                if mutated and mutated not in seen:
                    seen.add(mutated)
                    results.append(
                        MutatedPayload(
                            original=payload,
                            mutated=mutated,
                            mutations_applied=[mutation_type],
                            generation=1,
                        )
                    )
                    self.mutation_stats[mutation_type] += 1

            except Exception as e:
                logger.debug(f"Mutation failed: {e}")

        logger.debug(f"Generated {len(results)} mutations for payload")
        return results

    def mutate_all(
        self, payloads: list[str], mutations_per_payload: int = 5
    ) -> list[MutatedPayload]:
        """Mutate multiple payloads"""
        all_mutations = []

        for payload in payloads:
            mutations = self.mutate(payload, count=mutations_per_payload)
            all_mutations.extend(mutations)

        return all_mutations

    def evolve(
        self,
        seed_payloads: list[str],
        generations: int = 3,
        population_size: int = 20,
        fitness_func: Optional[Callable[[str], float]] = None,
    ) -> list[MutatedPayload]:
        """
        Evolutionary fuzzing - mutate over multiple generations.

        Args:
            seed_payloads: Initial payloads
            generations: Number of evolution generations
            population_size: Max population per generation
            fitness_func: Function to score payloads (higher = better)

        Returns:
            Final evolved population
        """
        population = [
            MutatedPayload(original=p, mutated=p, generation=0) for p in seed_payloads
        ]

        for gen in range(1, generations + 1):
            # Generate mutations from current population
            new_population = []

            for payload_obj in population:
                mutations = self.mutate(payload_obj.mutated, count=3)
                for m in mutations:
                    m.generation = gen
                new_population.extend(mutations)

            # Add original population
            population.extend(new_population)

            # Score and select
            if fitness_func:
                scored = [(p, fitness_func(p.mutated)) for p in population]
                scored.sort(key=lambda x: x[1], reverse=True)
                population = [p for p, _ in scored[:population_size]]
            else:
                # Random selection if no fitness function
                random.shuffle(population)
                population = population[:population_size]

            logger.debug(f"Generation {gen}: {len(population)} payloads")

        return population

    def record_success(self, mutated_payload: MutatedPayload):
        """Record a successful mutation for learning"""
        self.successful_mutations.append(mutated_payload)
        logger.info(
            f"Recorded successful mutation: {mutated_payload.mutations_applied}"
        )

    def _mutate_case(self, payload: str) -> str:
        """Random case swapping"""
        result = []
        for char in payload:
            if char.isalpha():
                if random.random() > 0.5:
                    char = char.swapcase()
            result.append(char)
        return "".join(result)

    def _mutate_whitespace(self, payload: str) -> str:
        """Insert whitespace variations"""
        ws = random.choice(self.WHITESPACE_CHARS)

        # Insert whitespace after < or before >
        positions = [
            (r"<", f"<{ws}"),
            (r">", f"{ws}>"),
            (r"=", f"{ws}={ws}"),
        ]

        pattern, replacement = random.choice(positions)
        return re.sub(pattern, replacement, payload, count=1)

    def _mutate_encoding(self, payload: str) -> str:
        """Apply character encoding"""
        encodings = {
            "<": ["%3C", "&#60;", "&#x3c;", "\\u003c", "\\x3c"],
            ">": ["%3E", "&#62;", "&#x3e;", "\\u003e", "\\x3e"],
            '"': ["%22", "&#34;", "&#x22;", "\\u0022"],
            "'": ["%27", "&#39;", "&#x27;", "\\u0027"],
            " ": ["%20", "+", "&#32;"],
        }

        result = payload
        char = random.choice(list(encodings.keys()))
        if char in result:
            encoded = random.choice(encodings[char])
            result = result.replace(char, encoded, 1)

        return result

    def _mutate_tag(self, payload: str) -> str:
        """Replace tag with alternative"""
        result = payload

        for tag, alternatives in self.TAG_ALTERNATIVES.items():
            pattern = rf"<{tag}(\s|>|/)"
            if re.search(pattern, result, re.IGNORECASE):
                alt = random.choice(alternatives)
                result = re.sub(
                    pattern, f"<{alt}\\1", result, count=1, flags=re.IGNORECASE
                )
                break

        return result

    def _mutate_attribute(self, payload: str) -> str:
        """Replace event handler with alternative"""
        result = payload

        for event, alternatives in self.EVENT_ALTERNATIVES.items():
            if event in result.lower():
                alt = random.choice(alternatives)
                result = re.sub(event, alt, result, count=1, flags=re.IGNORECASE)
                break

        return result

    def _mutate_quotes(self, payload: str) -> str:
        """Change quote characters"""
        current_quote = None
        for q in ['"', "'"]:
            if q in payload:
                current_quote = q
                break

        if current_quote:
            new_quote = random.choice(
                [q for q in self.QUOTE_CHARS if q != current_quote]
            )
            return payload.replace(current_quote, new_quote)

        return payload

    def _mutate_comments(self, payload: str) -> str:
        """Insert HTML/JS comments"""
        comments = ["/**/", "<!-->", "<!--", "-->", "//"]
        comment = random.choice(comments)

        # Insert at random position between tags
        if "<" in payload and ">" in payload:
            parts = payload.split(">")
            if len(parts) > 1:
                insert_pos = random.randint(0, len(parts) - 2)
                parts[insert_pos] += f">{comment}"
                return "".join(parts)

        return payload

    def _mutate_null_bytes(self, payload: str) -> str:
        """Insert null bytes"""
        null_chars = ["\x00", "%00", "\\0"]
        null = random.choice(null_chars)

        # Insert in tag name
        match = re.search(r"<(\w+)", payload)
        if match:
            tag = match.group(1)
            if len(tag) > 2:
                pos = random.randint(1, len(tag) - 1)
                new_tag = tag[:pos] + null + tag[pos:]
                return payload.replace(f"<{tag}", f"<{new_tag}", 1)

        return payload

    def _mutate_unicode(self, payload: str) -> str:
        """Use Unicode alternatives"""
        unicode_map = {
            "<": ["＜", "˂", "‹"],
            ">": ["＞", "˃", "›"],
            "/": ["／", "⁄"],
            "(": ["（", "❨"],
            ")": ["）", "❩"],
        }

        result = payload
        for char, alternatives in unicode_map.items():
            if char in result:
                alt = random.choice(alternatives)
                result = result.replace(char, alt, 1)
                break

        return result

    def _mutate_concatenation(self, payload: str) -> str:
        """Split strings with concatenation"""
        if "alert" in payload:
            variations = [
                "al" + "ert",
                "a]".replace("]", "l") + "ert",
                "ale" + "rt",
                "aler" + "t",
            ]
            return payload.replace("alert", random.choice(variations))

        return payload

    def _mutate_newlines(self, payload: str) -> str:
        """Insert newlines"""
        newlines = ["\n", "\r", "\r\n"]
        nl = random.choice(newlines)

        # Insert after = or before >
        if "=" in payload:
            return payload.replace("=", f"={nl}", 1)

        return payload

    def _mutate_tabs(self, payload: str) -> str:
        """Insert tabs"""
        tab_chars = ["\t", "%09", "&#9;"]
        tab = random.choice(tab_chars)

        # Insert in attribute
        if "=" in payload:
            return payload.replace("=", f"{tab}=", 1)

        return payload

    def get_statistics(self) -> dict[str, Any]:
        """Get fuzzer statistics"""
        return {
            "mutations_by_type": {m.value: c for m, c in self.mutation_stats.items()},
            "successful_mutations": len(self.successful_mutations),
            "total_mutations": sum(self.mutation_stats.values()),
        }

    def reset_statistics(self):
        """Reset statistics"""
        self.mutation_stats = {m: 0 for m in MutationType}
        self.successful_mutations.clear()
