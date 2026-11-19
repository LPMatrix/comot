# Language packs

A language pack holds one language's consent script as data: explanation items,
the six choices, and the teach-back questions. Adding a language means adding a
pack, not changing code.

**Status of what is here: draft skeleton, not reviewed.**

`pcm/pack.json` (Nigerian Pidgin) contains plain-English `source_en` text as a
starting point. `text` and `audio` are `null` on purpose. The wording should be
drafted with community members, not for them. Native speakers record the audio
(no text-to-speech), and a review group signs it off before release.
`comot.langpack.load_pack(...).missing_for_release()` lists exactly what is
still missing, and a pack is not releasable until that list is empty.

Rules the loader enforces:

- the six choices appear in the fixed order of the consent record;
- `explain.model_limit` comes before `choice.model_training`, so the
  participant hears that a trained model cannot be undone before choosing;
- 3 to 5 teach-back questions.

Study-specific wording (the study name, the health topic) comes from the
deploying organisation's ethics-approved text and is added by them. Receipts and
status messages never carry it.

## Adding a language

1. Copy `pcm/pack.json` to `<language>/pack.json` and change `language` and `pack_version`.
2. Keep the item ids and order. Replace `text` and `audio` only once the wording is reviewed and recorded.
3. Run `comot pack <language>/pack.json`.

Scripts, audio and schemas in this folder are intended for CC BY 4.0, subject to
what the community reviewers decide about the audio.
