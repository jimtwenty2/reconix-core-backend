from reconix_ai.knowledge.keywords import (
    PART_WEIGHT,
    document_vector,
    query_vector,
    token_index,
    tokens,
)


def test_joined_ids_are_kept_whole_and_split() -> None:
    words = dict(tokens("See CVE-2021-44228 and CWE-89."))

    assert words["cve-2021-44228"] == 1.0
    assert words["44228"] == PART_WEIGHT
    assert words["cwe-89"] == 1.0


def test_repeated_words_level_off() -> None:
    once, twice, ten = (weight_of("sql", "sql " * n) for n in (1, 2, 10))

    assert once < twice < ten < 2.2  # never more than k1 + 1


def test_query_vector_has_each_word_once() -> None:
    vector = query_vector("sql sql injection")

    assert len(vector.indices) == len(set(vector.indices)) == 2
    assert vector.values == [1.0, 1.0]


def test_token_index_is_stable() -> None:
    assert token_index("nmap") == token_index("nmap")
    assert token_index("nmap") != token_index("nuclei")


def weight_of(word: str, text: str) -> float:
    vector = document_vector(text)
    return dict(zip(vector.indices, vector.values, strict=True))[token_index(word)]
