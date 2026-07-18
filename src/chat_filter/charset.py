"""Character allowlist and stylized/homoglyph → plain replacement maps.

Forbidden glyphs are never listed: anything outside the allowlist is rejected.
Rejected emoji *sequences* (pride flag, UA regional indicators) are stored only
as integer codepoint tuples.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

# Forbiddden emojis
_REJECTED_EMOJI_SEQUENCES: Tuple[Tuple[int, ...], ...] = (
    (0x1F3F3, 0xFE0F, 0x200D, 0x1F308),  # white flag + ZWJ + rainbow
    (0x1F3F3, 0x200D, 0x1F308),
)

_REJECTED_FLAG_PAIRS: FrozenSet[Tuple[int, int]] = frozenset(
    {
        (0x1F1FA, 0x1F1E6),  # U + A
    }
)

_REGIONAL_A = 0x1F1E6
_REGIONAL_Z = 0x1F1FF

# Phonetic Extensions / IPA glyphs used as Cyrillic (and Latin) lookalikes.
# Keys are integer codepoints so the glyphs need not appear as source literals elsewhere.
_PHONETIC_LOOKALIKE_TO_CYR: Dict[int, str] = {
    0x1D00: "а",  # ᴀ
    0x1D04: "с",  # ᴄ
    0x1D07: "е",  # ᴇ
    0x1D0B: "к",  # ᴋ
    0x1D1B: "т",  # ᴛ
    0x1D20: "в",  # ᴠ
    0x1D22: "з",  # ᴢ
    0x1D26: "г",  # ᴦ
    0x1D27: "л",  # ᴧ
    0x1D28: "п",  # ᴨ
    0x1D29: "р",  # ᴩ
    0x028D: "м",  # ʍ turned w
    0x026F: "ш",  # ɯ turned m (visually ш-like in this bypass set)
    0x0299: "в",  # ʙ
    0x0278: "ф",  # ɸ
}

_PHONETIC_LOOKALIKE_TO_ASCII: Dict[int, str] = {
    0x1D00: "a",
    0x1D04: "c",
    0x1D07: "e",
    0x1D0B: "k",
    0x1D1B: "t",
    0x1D20: "v",
    0x1D22: "z",
    0x1D26: "g",
    0x1D27: "l",
    0x1D28: "p",
    0x1D29: "r",
    0x028D: "m",
    0x026F: "m",
    0x0299: "b",
    0x0278: "f",
}


def _range_set(start: int, end: int) -> set[int]:
    return set(range(start, end + 1))


def _build_allowed_codepoints() -> FrozenSet[int]:
    allowed: set[int] = set()

    # English
    allowed |= _range_set(ord("A"), ord("Z"))
    allowed |= _range_set(ord("a"), ord("z"))

    # Digits
    allowed |= _range_set(ord("0"), ord("9"))

    # Russian Cyrillic + Yo
    allowed |= _range_set(0x0410, 0x044F)  # А-я
    allowed.add(0x0401)  # Ё
    allowed.add(0x0451)  # ё

    # Typical keyboard punctuation (US) + common RU layout extras
    for ch in (
        " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        "«»№…–—±×÷€£¥©®™°§"
    ):
        allowed.add(ord(ch))

    # Whitespace used in messages
    for ch in "\t\n\r":
        allowed.add(ord(ch))

    # Fullwidth ASCII (FF01–FF5E) and ideographic space
    allowed |= _range_set(0xFF01, 0xFF5E)
    allowed.add(0x3000)

    # Mathematical Alphanumeric Symbols (yaytext-style)
    allowed |= _range_set(0x1D400, 0x1D7FF)

    # Enclosed alphanumerics / letterlike
    allowed |= _range_set(0x2460, 0x24FF)
    allowed |= _range_set(0x1F100, 0x1F1FF)  # enclosed alphanumeric supplement + regional
    allowed |= _range_set(0x1F150, 0x1F19A)  # negative squared Latin

    # Common emoji / symbol blocks (scalar codepoints; sequences checked separately)
    allowed |= _range_set(0x2600, 0x27BF)  # misc symbols + dingbats
    allowed |= _range_set(0x2300, 0x23FF)  # misc technical (some emoji)
    allowed |= _range_set(0x2B00, 0x2BFF)  # misc arrows/symbols
    allowed |= _range_set(0x1F000, 0x1F02F)  # mahjong
    allowed |= _range_set(0x1F0A0, 0x1F0FF)  # playing cards
    allowed |= _range_set(0x1F300, 0x1F5FF)  # misc pictographs
    allowed |= _range_set(0x1F600, 0x1F64F)  # emoticons
    allowed |= _range_set(0x1F680, 0x1F6FF)  # transport
    allowed |= _range_set(0x1F700, 0x1F77F)  # alchemical
    allowed |= _range_set(0x1F780, 0x1F7FF)  # geometric extended
    allowed |= _range_set(0x1F800, 0x1F8FF)  # arrows supplemental
    allowed |= _range_set(0x1F900, 0x1F9FF)  # supplemental symbols
    allowed |= _range_set(0x1FA00, 0x1FAFF)  # extended-A
    allowed |= _range_set(0x1FB00, 0x1FBFF)  # symbols for legacy computing

    # Variation selectors, ZWJ, skin-tone modifiers (for emoji sequences)
    allowed.add(0x200D)  # ZWJ
    allowed.add(0xFE0E)
    allowed.add(0xFE0F)
    allowed |= _range_set(0x1F3FB, 0x1F3FF)  # skin tones
    allowed |= _range_set(0xE0020, 0xE007F)  # tags (for some flag sequences)

    # Combining marks sometimes used with emoji / stylized text
    allowed |= _range_set(0x0300, 0x036F)

    # Greek letters used as lookalikes (mapped for matching)
    allowed |= {
        0x03B1,
        0x0391,
        0x03BF,
        0x039F,
        0x03C1,
        0x03A1,
        0x03C5,
        0x03A5,
        0x03C7,
        0x03A7,
        0x03B5,
        0x0395,
        0x03B9,
        0x0399,
        0x03BD,
        0x039D,
        0x03BC,
        0x039C,
        0x03C0,
        0x03A0,
        0x03C4,
        0x03A4,
        0x03B3,
        0x0393,
        0x03C3,
        0x03A3,
        0x03C6,
        0x03A6,
    }

    # Phonetic Extensions / IPA small-caps & turned letters used as Cyrillic lookalikes
    allowed |= set(_PHONETIC_LOOKALIKE_TO_CYR.keys())

    return frozenset(allowed)


ALLOWED_CODEPOINTS: FrozenSet[int] = _build_allowed_codepoints()


def _add_latin_block(mapping: Dict[int, str], start: int, upper: bool) -> None:
    base = ord("A") if upper else ord("a")
    for i in range(26):
        mapping[start + i] = chr(base + i)


def _add_digit_block(mapping: Dict[int, str], start: int) -> None:
    for i in range(10):
        mapping[start + i] = chr(ord("0") + i)


def _build_replacement_map() -> Dict[int, str]:
    """Map allowed stylized / lookalike codepoints to plain a–z / digits / Cyrillic."""
    m: Dict[int, str] = {}

    # Mathematical Alphanumeric Symbols — letter styles (gaps for reserved slots).
    # Bold
    _add_latin_block(m, 0x1D400, True)
    _add_latin_block(m, 0x1D41A, False)
    # Italic (h is at 0x210E)
    _add_latin_block(m, 0x1D434, True)
    for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
        cp = 0x1D44E + i
        if ch == "h":
            m[0x210E] = "h"
        else:
            # Italic small: a–g 1D44E–1D454, i–z 1D456–1D467 (skip h slot)
            if i < 7:
                m[0x1D44E + i] = ch
            elif i > 7:
                m[0x1D456 + (i - 8)] = ch
    # Bold italic
    _add_latin_block(m, 0x1D468, True)
    _add_latin_block(m, 0x1D482, False)
    # Script
    _add_latin_block(m, 0x1D49C, True)
    _add_latin_block(m, 0x1D4B6, False)
    # Bold script
    _add_latin_block(m, 0x1D4D0, True)
    _add_latin_block(m, 0x1D4EA, False)
    # Fraktur
    _add_latin_block(m, 0x1D504, True)
    _add_latin_block(m, 0x1D51E, False)
    # Double-struck
    _add_latin_block(m, 0x1D538, True)
    _add_latin_block(m, 0x1D552, False)
    # Bold fraktur
    _add_latin_block(m, 0x1D56C, True)
    _add_latin_block(m, 0x1D586, False)
    # Sans-serif
    _add_latin_block(m, 0x1D5A0, True)
    _add_latin_block(m, 0x1D5BA, False)
    # Sans-serif bold
    _add_latin_block(m, 0x1D5D4, True)
    _add_latin_block(m, 0x1D5EE, False)
    # Sans-serif italic
    _add_latin_block(m, 0x1D608, True)
    _add_latin_block(m, 0x1D622, False)
    # Sans-serif bold italic
    _add_latin_block(m, 0x1D63C, True)
    _add_latin_block(m, 0x1D656, False)
    # Monospace
    _add_latin_block(m, 0x1D670, True)
    _add_latin_block(m, 0x1D68A, False)

    # Math digits
    _add_digit_block(m, 0x1D7CE)  # bold
    _add_digit_block(m, 0x1D7D8)  # double-struck
    _add_digit_block(m, 0x1D7E2)  # sans
    _add_digit_block(m, 0x1D7EC)  # sans bold
    _add_digit_block(m, 0x1D7F6)  # monospace

    # Fullwidth Latin / digits / common punct → ASCII
    for i in range(0x21, 0x7F):
        m[0xFF00 + i - 0x20] = chr(i)

    # Circled Latin (Ⓐ–Ⓩ, ⓐ–ⓩ)
    for i in range(26):
        m[0x24B6 + i] = chr(ord("A") + i)
        m[0x24D0 + i] = chr(ord("a") + i)

    # Negative squared Latin (🅰 is special; 🅐–🅩)
    for i in range(26):
        m[0x1F150 + i] = chr(ord("A") + i)

    # Regional indicator symbols → a–z (letter-emoji / flag letters)
    for i in range(26):
        m[_REGIONAL_A + i] = chr(ord("a") + i)

    # Keycap base digits (combined with FE0F 20E3 in sequences — scalar digit still maps)
    # Parenthesized / enclosed digits already partially covered by NFKC.

    # Latin → Cyrillic (RU matching path) + leet
    latin_to_cyr = {
        "a": "а",
        "b": "б",
        "c": "с",
        "d": "д",
        "e": "е",
        "f": "ф",
        "g": "г",
        "h": "х",
        "i": "и",
        "k": "к",
        "l": "л",
        "m": "м",
        "n": "н",
        "o": "о",
        "p": "п",
        "r": "р",
        "s": "с",
        "t": "т",
        "u": "у",
        "v": "в",
        "w": "в",
        "x": "х",
        "y": "у",  # also try й via alternate form
        "z": "з",
        "0": "о",
        "1": "и",
        "3": "е",
        "4": "а",
        "@": "а",
    }
    for src, dst in latin_to_cyr.items():
        m[ord(src)] = dst
        if src.isalpha():
            m[ord(src.upper())] = dst

    # Cyrillic identity / ё→е
    for cp in range(0x0410, 0x0450):
        ch = chr(cp)
        m[cp] = ch.lower().replace("ё", "е")
    m[0x0401] = "е"
    m[0x0451] = "е"

    # Greek lookalikes
    greek = {
        0x03B1: "а",
        0x0391: "а",
        0x03BF: "о",
        0x039F: "о",
        0x03C1: "р",
        0x03A1: "р",
        0x03C5: "у",
        0x03A5: "у",
        0x03C7: "х",
        0x03A7: "х",
        0x03B5: "е",
        0x0395: "е",
        0x03B9: "и",
        0x0399: "и",
        0x03BD: "н",
        0x039D: "н",
        0x03BC: "м",
        0x039C: "м",
        0x03C0: "п",
        0x03A0: "п",
        0x03C4: "т",
        0x03A4: "т",
        0x03B3: "г",
        0x0393: "г",
        0x03C3: "с",
        0x03A3: "с",
        0x03C6: "ф",
        0x03A6: "ф",
    }
    m.update(greek)
    m.update(_PHONETIC_LOOKALIKE_TO_CYR)

    return m


# Plain ASCII path: stylized → ascii letter (no Cyrillicization)
def _build_ascii_replacement_map() -> Dict[int, str]:
    m: Dict[int, str] = {}
    _add_latin_block(m, 0x1D400, True)
    _add_latin_block(m, 0x1D41A, False)
    _add_latin_block(m, 0x1D434, True)
    for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
        if ch == "h":
            m[0x210E] = "h"
        elif i < 7:
            m[0x1D44E + i] = ch
        elif i > 7:
            m[0x1D456 + (i - 8)] = ch
    for start in (
        0x1D468,
        0x1D49C,
        0x1D4D0,
        0x1D504,
        0x1D538,
        0x1D56C,
        0x1D5A0,
        0x1D5D4,
        0x1D608,
        0x1D63C,
        0x1D670,
    ):
        _add_latin_block(m, start, True)
    for start in (
        0x1D482,
        0x1D4B6,
        0x1D4EA,
        0x1D51E,
        0x1D552,
        0x1D586,
        0x1D5BA,
        0x1D5EE,
        0x1D622,
        0x1D656,
        0x1D68A,
    ):
        _add_latin_block(m, start, False)
    for start in (0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6):
        _add_digit_block(m, start)
    for i in range(0x21, 0x7F):
        m[0xFF00 + i - 0x20] = chr(i)
    for i in range(26):
        m[0x24B6 + i] = chr(ord("A") + i)
        m[0x24D0 + i] = chr(ord("a") + i)
        m[0x1F150 + i] = chr(ord("A") + i)
        m[_REGIONAL_A + i] = chr(ord("a") + i)
    # Identity for ASCII letters/digits
    for cp in range(ord("A"), ord("Z") + 1):
        m[cp] = chr(cp).lower()
    for cp in range(ord("a"), ord("z") + 1):
        m[cp] = chr(cp)
    for cp in range(ord("0"), ord("9") + 1):
        m[cp] = chr(cp)
    m.update(_PHONETIC_LOOKALIKE_TO_ASCII)
    return m


REPLACEMENT_TO_CYRILLIC: Dict[int, str] = _build_replacement_map()
REPLACEMENT_TO_ASCII: Dict[int, str] = _build_ascii_replacement_map()


def has_disallowed_characters(text: str) -> bool:
    """True if any scalar codepoint is outside the allowlist, or a rejected emoji/flag sequence appears."""
    cps = [ord(ch) for ch in text]
    n = len(cps)

    i = 0
    while i < n:
        # Rejected multi-codepoint emoji sequences
        for seq in _REJECTED_EMOJI_SEQUENCES:
            sl = len(seq)
            if i + sl <= n and tuple(cps[i : i + sl]) == seq:
                return True

        # Rejected flag pair (regional indicators)
        if i + 1 < n and (_REGIONAL_A <= cps[i] <= _REGIONAL_Z):
            pair = (cps[i], cps[i + 1])
            if pair in _REJECTED_FLAG_PAIRS:
                return True
            # Valid flag pair: consume both if second is also regional
            if _REGIONAL_A <= cps[i + 1] <= _REGIONAL_Z:
                if cps[i] not in ALLOWED_CODEPOINTS or cps[i + 1] not in ALLOWED_CODEPOINTS:
                    return True
                i += 2
                continue

        if cps[i] not in ALLOWED_CODEPOINTS:
            return True
        i += 1

    return False


def map_to_cyrillic_letters(text: str) -> str:
    """NFKC + map to Cyrillic/leet letters; drop non-letters (emoji noise stripped)."""
    import unicodedata

    text = unicodedata.normalize("NFKC", text)
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in REPLACEMENT_TO_CYRILLIC:
            mapped = REPLACEMENT_TO_CYRILLIC[cp]
            if mapped.isalpha() or mapped.isdigit():
                out.append(mapped.lower())
        elif ch.isalpha() or ch.isdigit():
            # Unmapped letter: keep lowercase (may be rare scripts — already allowlisted)
            out.append(ch.lower())
    return "".join(out)


def map_to_ascii_letters(text: str) -> str:
    """NFKC + map stylized → ASCII letters/digits for English dictionary matching."""
    import unicodedata

    text = unicodedata.normalize("NFKC", text)
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in REPLACEMENT_TO_ASCII:
            mapped = REPLACEMENT_TO_ASCII[cp]
            if mapped.isascii() and (mapped.isalpha() or mapped.isdigit()):
                out.append(mapped.lower())
        elif ch.isascii() and (ch.isalpha() or ch.isdigit()):
            out.append(ch.lower())
    return "".join(out)


# Single-position swaps for leet / latin / greek ambiguity after primary mapping.
# у↔и: latin u; е→з: digit 3 as з; р→п: greek rho used as п-lookalike.
_AMBIGUOUS_LETTER_SWAPS: Tuple[Tuple[str, str], ...] = (
    ("у", "и"),
    ("и", "у"),
    ("е", "з"),
    ("р", "п"),
)


def cyrillic_alternates(normalized: str) -> Tuple[str, ...]:
    """Expand normalized text with common leet/latin/homoglyph ambiguities."""
    alts = {normalized}
    if "хуу" in normalized:
        alts.add(normalized.replace("хуу", "хуй"))
    chars = list(normalized)
    for i in range(1, len(chars)):
        if chars[i] == "у" and chars[i - 1] == "х":
            trial = chars.copy()
            trial[i] = "й"
            alts.add("".join(trial))

    # One substitution each — enough for пuдорaс / 3еленский / ρутин style bypasses.
    seed = list(alts)
    for form in seed:
        form_chars = list(form)
        for i, ch in enumerate(form_chars):
            for src, dst in _AMBIGUOUS_LETTER_SWAPS:
                if ch == src:
                    trial = form_chars.copy()
                    trial[i] = dst
                    alts.add("".join(trial))
    return tuple(alts)
