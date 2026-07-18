"""Content check engine: allowlist, normalization, profanity, politics, blocklist."""

from __future__ import annotations

import re
from threading import RLock
from typing import Set

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
    "пизда",
    "пиздец",
    "хуй",
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
    "теракт",
    "сиськ",
    "минет",
    "отсос",
}

_ADULT_TERMS: Set[str] = {
    "порно",
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

_PHRASE_PATTERNS = (
    # существовало по приколу, ладно, не буду цензурить на ровном месте :)
    # re.compile(r"max\s*is\s*better", re.IGNORECASE),
    # re.compile(r"макс\s*лучше", re.IGNORECASE),
    # re.compile(r"fromchat\s*г[ао]вно", re.IGNORECASE),
    # re.compile(r"фромчат\s*г[ао]вно", re.IGNORECASE),
    # re.compile(r"18\+"),
    # re.compile(r"xxx", re.IGNORECASE),
    re.compile(r"(?<![a-zа-яё])сво(?![a-zа-яё])", re.IGNORECASE),
    re.compile(
        r"(?<![a-zа-яё])[zзᴢ][\s\-_.]*[vｖᴠв](?![a-zа-яё])",
        re.IGNORECASE,
    )
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


def _ru_terms_hit(normalized: str) -> bool:
    terms = set(_STATIC_TERMS)
    terms |= {w.lower().replace(" ", "") for w in blocklist_store.get_blocklist()}
    terms |= set(_POLITICS_TERMS)
    terms -= _WHITELIST

    for form in cyrillic_alternates(normalized):
        if form in _WHITELIST:
            return False
        if _substring_hit(form, terms):
            return True
        for term in terms:
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
    for pattern in _PHRASE_PATTERNS:
        if pattern.search(lowered):
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

    if cyr and _ru_terms_hit(cyr):
        return False

    ascii_form = map_to_ascii_letters(text)
    if ascii_form and _english_hit(ascii_form):
        return False

    # Custom blocklist on ascii glued form too
    block = {w.lower().replace(" ", "") for w in blocklist_store.get_blocklist()}
    if ascii_form and _substring_hit(ascii_form, block):
        return False

    return True
