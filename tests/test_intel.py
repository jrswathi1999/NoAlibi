"""Policy text extraction, quote validation and deterministic provider detection."""

from datetime import UTC, datetime

from intel.claims import provider_claim, relevant_context, sentences, validate_quote
from intel.policy import PolicyDoc, guess_first_party, html_to_text

POLICY = (
    "We collect account details. We use OpenAI's models to power the AI assistant feature.\n"
    "We may share information with trusted service providers who help us operate.\n"
    "Your notes are stored on your device and never leave it unless you turn on sync."
)


def _doc(text: str = POLICY) -> PolicyDoc:
    return PolicyDoc(
        url="https://notes.example/privacy", text=text, sha256="x", fetched_at=datetime.now(UTC)
    )


def test_html_to_text_drops_scripts_and_keeps_paragraphs():
    html = "<html><head><title>x</title></head><body><nav>Menu</nav><script>evil()</script><h1>Privacy</h1><p>We keep&nbsp;data.</p></body></html>"
    text = html_to_text(html)
    assert "evil" not in text and "x" not in text.split("\n")
    assert "Privacy" in text and "We keep data." in text


def test_exact_quote_passes_and_invented_quote_fails():
    sents = sentences(POLICY)
    assert validate_quote(
        "We may share information with trusted service providers who help us operate.",
        POLICY,
        sents,
    ) == (
        "We may share information with trusted service providers who help us operate.",
        "exact",
    )
    assert validate_quote("We sell your notes to advertisers for profit.", POLICY, sents) is None


def test_fuzzy_quote_is_replaced_by_the_real_sentence():
    sents = sentences(POLICY)
    quote, match = validate_quote(
        "Your notes are stored on your device and never leave it unless you turn sync on.",
        POLICY,
        sents,
    )
    assert match == "fuzzy"
    assert quote in POLICY


def test_provider_detection_is_deterministic():
    found = provider_claim(_doc(), sentences(POLICY))
    assert found["value"] == "yes" and found["providers"] == ["OpenAI"]
    assert found["quote"] in POLICY


def test_no_named_provider_quotes_the_vague_sharing_sentence():
    text = "We may share information with trusted service providers who help us operate the AI features."
    found = provider_claim(_doc(text), sentences(text))
    assert found["value"] == "no" and found["providers"] == []


def test_relevant_context_respects_limit():
    ctx = relevant_context(POLICY * 50, ("device", "local"), limit=500)
    assert 0 < len(ctx) <= 600


def test_first_party_guess():
    fp = guess_first_party(
        "com.anthropic.claudefordesktop", "https://www.anthropic.com/legal/privacy"
    )
    assert "anthropic.com" in fp and "claude.ai" in fp
    assert "kiro.dev" in guess_first_party("dev.kiro.desktop", None)
