import json
from pathlib import Path

import pytest

from comot.langpack import PackError, load_pack

PACK = Path(__file__).parent.parent / "language_packs" / "pcm" / "pack.json"


def test_shipped_pidgin_draft_loads_but_is_not_releasable():
    pack = load_pack(PACK)
    assert pack.language == "pcm"
    assert not pack.releasable
    reasons = pack.missing_for_release()
    assert any("signed_off" in r for r in reasons)
    assert any("native-speaker audio" in r for r in reasons)


def test_model_limit_is_heard_before_the_training_choice():
    ids = load_pack(PACK).item_ids()
    assert ids.index("explain.model_limit") < ids.index("choice.model_training")


def _edit(tmp_path, fn):
    raw = json.loads(PACK.read_text(encoding="utf-8"))
    fn(raw)
    p = tmp_path / "pack.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    return p


def test_wrong_order_is_rejected(tmp_path):
    def swap(raw):
        ids = [i["id"] for i in raw["items"]]
        a, b = ids.index("explain.model_limit"), ids.index("choice.model_training")
        raw["items"][a], raw["items"][b] = raw["items"][b], raw["items"][a]
    with pytest.raises(PackError):
        load_pack(_edit(tmp_path, swap))


def test_pack_without_enough_teachback_is_rejected(tmp_path):
    def cut(raw):
        raw["items"] = [i for i in raw["items"] if i["id"] not in ("teachback.3", "teachback.4")]
    with pytest.raises(PackError, match="teach-back"):
        load_pack(_edit(tmp_path, cut))


def test_complete_signed_off_pack_is_releasable(tmp_path):
    def finish(raw):
        raw["status"] = "signed_off"
        raw["review"]["signed_off_by"] = ["reviewer-1", "reviewer-2"]
        for i in raw["items"]:
            i["text"], i["audio"] = "approved wording", f"audio/{i['id']}.ogg"
    assert load_pack(_edit(tmp_path, finish)).releasable
