import warnings

import pytest

from ahaudit import manifest
from ahaudit.model import AuthzSubject


def test_american_spelling_is_accepted():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        h = manifest.from_dict({"harness": {
            "name": "x",
            "authorization": {"subject": "requesting-principal"}}})
    assert h.authorisation.subject is AuthzSubject.REQUESTING_PRINCIPAL
    assert any("alias" in str(w.message) for w in caught)


def test_preferred_spelling_does_not_warn():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        manifest.from_dict({"harness": {
            "name": "x",
            "authorisation": {"subject": "requesting-principal"}}})
    assert not [w for w in caught if "alias" in str(w.message)]


def test_both_spellings_is_an_error():
    with pytest.raises(manifest.ManifestError) as e:
        manifest.from_dict({"harness": {
            "name": "x",
            "authorisation": {}, "authorization": {}}})
    assert "keep one" in str(e.value)


def test_other_misspellings_are_still_errors():
    with pytest.raises(manifest.ManifestError):
        manifest.from_dict({"harness": {"name": "x",
                                        "authorisaton": {}}})
