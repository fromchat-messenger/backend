"""Content check engine: allowlist, normalization, profanity, politics, blocklist."""

from __future__ import annotations

import re
from threading import RLock
from typing import Set, Tuple

from better_profanity import Profanity

from . import blocklist as blocklist_store
from .charset import (
    cyrillic_alternates,
    has_disallowed_characters,
    map_to_ascii_letters,
    map_to_cyrillic_letters,
)

# все эти плохие слова писал не я.
# слова не являются моим или чьем-то другим личным мнением.
# использовано только для фильтрации сообщений в общем чате и другой публичной информации в мессенджере.
# - denis0001-dev, владелец проекта

_CUSTOM_RU_TERMS: Set[str] = {
    "бляд",
    "блять",
    "бля",
    "сука",
    "суки",
    "сучка",
    "мразь",
    "ебан",
    "ебать",
    "ебёт",
    "ебет",
    "ебаная",
    "уёбок",
    "уебок",
    "уебище",
    "еблищ",
    "еблахищ",
    "ебал",
    "пенис",
    "пизда",
    "пиздец",
    "хуй",
    "хуи",
    "хуя",
    "хуе",
    "хуё",
    "хуйня",
    "хуйло",
    "хер",
    "гондон",
    "долбоёб",
    "долбоеб",
    "дебил",
    "идиот",
    "член",
    "проститутка",
    "проститутки",
    "урод",
    "хуесос",
    "хуесосы",
    "хуесосов",
    "хуесоса",
    "пидор",
    "пидоры",
    "пидорас",
    "пидорасы",
    "пидорасов",
    "педераст",
    "педик",
    "ниггер",
    "жид",
    "чурк",
    "черножоп",
    "узкоглаз",
    "пиндос",
    "хохол",
    "москал",
    "бульбаш",
    "гомик",
    "шлюх",
    "курва",
    "манда",
    "олигофрен",
    "шизоид",
    "аутист",
    "убейсебя",
    "убей",
    "убью",
    "повесься",
    "сдохни",
    "издохни",
    "сгинь",
    "выпейяду",
    "взорвать",
    "взорву",
    "теракт",
    "сиськ",
    "минет",
    "отсос",
}

_ADULT_TERMS: Set[str] = {
    "порно",
    "порн",
    "порню",
    "порнуха",
    "эротика",
    "эротический",
    "секс",
    "сексуальный",
    "инцест",
    "порнография",
    "порностудия",
    "порновидео",
    "порносайт",
    "сексчат",
    "сексчатик",
    "секслайв",
    "сексвидео",
}

_POLITICS_TERMS: Set[str] = {
    "путин",
    "зеленск",
    "навальн",
    "медведев",
    "байден",
    "трамп",
    "спецоперац",
    "мобилизац",
    "крымнаш",
    "донбасс",
    "днр",
    "лнр",
    "украин",
    "русофоб",
    "либерал",
    "лгбт",
    "lgbt",
    "евросоюз",
    "госдум",
    "единаяроссия",
    "оппозиц",
    "выборыпрезидента",
    "референдум",
    "нато",
    "фашизм",
    "фашист",
    "нацизм",
    "нацист",
    "бандер",
    "майдан",
    "ватник",
    "укроп",
}

_WHITELIST: Set[str] = {
    "говно",
}

_STATIC_TERMS: Set[str] = {t.lower() for t in (_CUSTOM_RU_TERMS | _ADULT_TERMS)}

# Embedded Latin profanity (better_profanity matches whole tokens only).
_CUSTOM_EN_TERMS: Set[str] = {
    "porn",
    "xxx",
}

_PHRASE_PATTERNS = (
    re.compile(r"max\s*is\s*better", re.IGNORECASE),
    re.compile(r"макс\s*лучше", re.IGNORECASE),
    re.compile(r"fromchat\s*г[ао]вно", re.IGNORECASE),
    re.compile(r"фромчат\s*г[ао]вно", re.IGNORECASE),
    re.compile(r"18\+"),
    re.compile(r"xxx", re.IGNORECASE),
    # Whole-token СВО / SVO only (avoid своих / svoboda).
    re.compile(r"(?<![a-zа-яё])(?:сво|svo)(?![a-zа-яё])", re.IGNORECASE),
    # Latin/Cyrillic/phonetic Z+V military symbols as a token.
    re.compile(
        r"(?<![a-zа-яё])[zзᴢ][\s\-_.]*[vｖᴠв](?![a-zа-яё])",
        re.IGNORECASE,
    ),
    # Latin Z-O-V propaganda symbol (do not match Cyrillic «зов»).
    re.compile(
        r"(?<![a-zа-яё])z[\s\-_.]*o[\s\-_.]*v(?![a-zа-яё])",
        re.IGNORECASE,
    ),
    # Stretched Latin «porn» (Pooornooo-style).
    re.compile(r"p[\s\-_.]*o{2,}[\s\-_.]*r[\s\-_.]*n[\s\-_.]*o+", re.IGNORECASE),
    # Stretched Cyrillic «порно» (поооорноооо-style).
    re.compile(
        r"п[\s\-_.]*о{2,}[\s\-_.]*р[\s\-_.]*н[\s\-_.]*о+",
        re.IGNORECASE,
    ),
    # Latin «porn» / leet (incl. n0rn0 first-letter swap).
    re.compile(
        r"(?<![a-z])[pn][\s\-_.]*[o0][\s\-_.]*r[\s\-_.]*n[\s\-_.]*[o0](?![a-z])",
        re.IGNORECASE,
    ),
)

# Matched on whitespace-stripped text to catch «п o р н o» without glued false positives.
_COMPACT_PHRASE_PATTERNS = (
    re.compile(r"по{1,}р{1}н{1}о{1,}"),
    re.compile(r"p[o0]{1,}r{1}n{1}[o0]{1,}"),
    re.compile(r"p[rр][o0]{1,}n[o0]{1,}"),
)

_lock = RLock()
_profanity = Profanity()
_blocklist_sig: tuple[str, ...] | None = None


def _rebuild_english_dict() -> None:
    global _profanity, _blocklist_sig
    with _lock:
        words = tuple(sorted(blocklist_store.get_blocklist()))
        if _blocklist_sig == words and _blocklist_sig is not None:
            return
        p = Profanity()
        p.load_censor_words()
        for w in _WHITELIST:
            try:
                p.remove_censor_words([w])
            except AttributeError:
                pass
        extra = set(_STATIC_TERMS) | set(words)
        extra -= _WHITELIST
        if extra:
            p.add_censor_words(list(extra))
        _profanity = p
        _blocklist_sig = words


def _substring_hit(text: str, terms: Set[str]) -> bool:
    for term in terms:
        if term and term in text:
            return True
    return False


def _subsequence_hit(text: str, term: str) -> bool:
    if len(term) < 3:
        return False
    if len(term) <= 3:
        max_span_ratio = 1.3
    elif len(term) == 4:
        max_span_ratio = 1.4
    elif len(term) <= 5:
        max_span_ratio = 1.5
    else:
        max_span_ratio = 1.8

    word_chars = list(term)
    text_chars = list(text)
    i = 0
    j = 0
    seq_start = None
    while i < len(text_chars) and j < len(word_chars):
        if text_chars[i] == word_chars[j]:
            if seq_start is None:
                seq_start = i
            j += 1
            if j == len(word_chars):
                span_length = i + 1 - seq_start
                if span_length <= int(len(term) * max_span_ratio):
                    return True
                next_start = seq_start + 1
                seq_start = None
                j = 0
                i = next_start
                continue
        i += 1
    return False


def _token_cyrillic_alternate_forms(text: str) -> Tuple[str, ...]:
    """Per whitespace token: normalized Cyrillic + leet alternates (for subsequence only)."""
    forms: Set[str] = set()
    for token in re.split(r"\s+", text.strip()):
        if not token:
            continue
        token_cyr = map_to_cyrillic_letters(token)
        if token_cyr:
            forms.update(cyrillic_alternates(token_cyr))
    return tuple(forms)


def _token_ascii_forms(text: str) -> Tuple[str, ...]:
    forms: Set[str] = set()
    for token in re.split(r"\s+", text.strip()):
        if not token:
            continue
        token_ascii = map_to_ascii_letters(token)
        if token_ascii:
            forms.add(token_ascii)
    return tuple(forms)


def _concatenated_token_cyrillic(text: str) -> str:
    parts: list[str] = []
    for token in re.split(r"\s+", text.strip()):
        if not token:
            continue
        token_cyr = map_to_cyrillic_letters(token)
        if token_cyr:
            parts.append(token_cyr)
    return "".join(parts)


def _term_match_forms(text: str, normalized: str) -> Tuple[str, ...]:
    """Token-wise forms when input has spaces; full glued alternates otherwise."""
    if re.search(r"\s", text):
        return _token_cyrillic_alternate_forms(text)
    return tuple(cyrillic_alternates(normalized))


def _exact_token_term_hit(text: str, terms: Set[str]) -> bool:
    for token in re.split(r"\s+", text.strip()):
        if not token:
            continue
        token_cyr = map_to_cyrillic_letters(token)
        if not token_cyr:
            continue
        for form in cyrillic_alternates(token_cyr):
            if form in terms:
                return True
    return False


def _ru_terms_hit(text: str, normalized: str, match_forms: Tuple[str, ...]) -> bool:
    terms = set(_STATIC_TERMS)
    terms |= {w.lower().replace(" ", "") for w in blocklist_store.get_blocklist()}
    terms |= set(_POLITICS_TERMS)
    terms -= _WHITELIST

    long_terms = {t for t in terms if len(t) >= 5}
    # Short stems only as an exact token (avoid «импортный», «опорный», etc.).
    short_token_terms = {t for t in terms if len(t) == 4 and t in _ADULT_TERMS}

    if short_token_terms and _exact_token_term_hit(text, short_token_terms):
        return True

    for form in match_forms:
        if form in _WHITELIST:
            continue
        if _substring_hit(form, terms - short_token_terms):
            return True
        for term in terms - short_token_terms:
            if _subsequence_hit(form, term):
                return True

    # Spaced bypass: «по рно» → concat «порно»; substring only (no subsequence).
    if re.search(r"\s", text):
        concat = _concatenated_token_cyrillic(text)
        if concat and concat not in _WHITELIST:
            if _substring_hit(concat, long_terms):
                return True
            for form in cyrillic_alternates(concat):
                if form in _WHITELIST:
                    continue
                if _substring_hit(form, long_terms):
                    return True
    return False


def _ascii_terms_hit(text: str, ascii_form: str) -> bool:
    if not ascii_form:
        return False
    if _english_hit(ascii_form):
        return True

    en_terms = set(_CUSTOM_EN_TERMS)
    en_terms |= {w.lower().replace(" ", "") for w in blocklist_store.get_blocklist() if w.isascii()}
    if re.search(r"\s", text):
        forms = _token_ascii_forms(text)
    else:
        forms = (ascii_form,)
    for form in forms:
        if _substring_hit(form, en_terms):
            return True
        for term in en_terms:
            if _subsequence_hit(form, term):
                return True
    return False


def _english_hit(ascii_text: str) -> bool:
    if not ascii_text:
        return False
    _rebuild_english_dict()
    censored = _profanity.censor(ascii_text, censor_char="*")
    return "*" in censored


def _phrase_hit(text: str) -> bool:
    lowered = text.lower()
    compact = re.sub(r"[\s\-_.]+", "", lowered)
    for pattern in _PHRASE_PATTERNS:
        if pattern.search(lowered):
            return True
    for pattern in _COMPACT_PHRASE_PATTERNS:
        if pattern.search(compact):
            return True
    return False


def is_allowed(text: str) -> bool:
    """Return True if text may be published; False if it should be rejected."""
    if not text:
        return True

    if has_disallowed_characters(text):
        return False

    if _phrase_hit(text):
        return False

    cyr = map_to_cyrillic_letters(text)
    if cyr and cyr in _WHITELIST:
        return True

    if cyr and _ru_terms_hit(text, cyr, _term_match_forms(text, cyr)):
        return False

    ascii_form = map_to_ascii_letters(text)
    if ascii_form and _ascii_terms_hit(text, ascii_form):
        return False

    # Custom blocklist on ascii glued form too
    block = {w.lower().replace(" ", "") for w in blocklist_store.get_blocklist()}
    if ascii_form and _substring_hit(ascii_form, block):
        return False

    return True
