# Legal notes

How Comot lines up with Nigerian data protection law, and what it leaves to you. **This is not legal advice.** It is a developer's reading of the texts, written so a lawyer can check it quickly. Where a reading is uncertain it says so.

**What was read.** The [Nigeria Data Protection Act 2023](https://www.dataguidance.com/sites/default/files/data_protection_act_2023.pdf) (the Act) and the Nigeria Data Protection Commission's [General Application and Implementation Directive 2025](https://ndpc.gov.ng/wp-content/uploads/2025/07/NDP-ACT-GAID-2025-MARCH-20TH.pdf) (the GAID), both fetched on 20 November 2026. Section and article numbers below are from those texts. Wording is paraphrased, not quoted.

**What was not.** GAID Schedules 4 and 5, the Commission's own adequacy decisions (none were found), the National Code of Health Research Ethics and the National Health Act 2014 in their primary text, case law, and any law outside Nigeria.

## What the law asks and what Comot does

| The law | Source | In Comot |
| --- | --- | --- |
| Consent can be spoken. It must be a clear yes, not pre-ticked, and silence is not consent | Act s.26(3), s.26(7) | **Enforced.** Silence is stored as no, and capture methods are spoken or button, never a default |
| The controller must be able to prove consent, and keep a proper record | Act s.26(1); GAID Art. 17(6) | **Recorded.** Each consent is a hash-chained, append-only version with script version, language, capture method, who captured it and the teach-back score |
| Consent must be for specific purposes | Act s.25(1)(a), s.30(1)(a) | **Enforced.** Six separate choices, checked per use on every derived copy |
| Tell the person they can withdraw before they consent | Act s.26(4) | **Enforced in language packs.** `explain.withdraw` must come before the first choice |
| Withdrawing must be as easy as consenting, and earlier processing stays lawful | Act s.26(5), s.35(2); GAID Art. 17(7)(b) | **Enforced.** Withdraw by code, health worker or status line with no reason asked. Receipts say published results are unchanged |
| Erase on withdrawal, and make sure outside holders erase too | Act s.34(2); GAID Art. 38(1)(b), 38(3) | **Tracked.** One action per copy, including a notice the holder must confirm |
| Tell people who is collecting, why, who gets it, how long it is kept, their rights and that they can complain to the Commission, in a form they understand | Act s.27(1); GAID Art. 27 | **Gated.** A language pack cannot be released without an explanation for each, in order |
| Saying no must not cost the person anything | GAID Art. 17(7)(c) | **Gated.** `explain.no_penalty` is required. Whether the project honours it is a process matter |
| A child's consent comes from a parent or guardian, and age and consent are verified | Act s.31(1)-(3) | **Recorded.** Guardian consent and the child's assent are both required, and `guardian_verification` says how age and consent were checked. No ID document or number is stored |
| Before a copy goes to a country without adequate protection, the person is told the risks and consents. The controller records the basis for each transfer | Act s.41(2), s.43(1)(a); GAID Art. 18(1)(e) | **Enforced and recorded.** Every copy held outside needs a destination country and a basis. The basis `consent_after_risk_notice` is refused unless every source participant was recorded as told the risks. A language pack needs `explain.transfer_risk` before the sharing choice |
| Keep data no longer than needed | Act s.24(1)(d) | **Partly.** Retention is a choice (`retain_after_project`) and deletion is tracked. Setting the period is yours |
| Breach notice to the Commission within 72 hours | Act s.40 | **Not covered.** Comot has no breach tooling |

### Transfer bases

`TRANSFER_BASES` lists `within_nigeria`, `adequacy_decision`, `approved_instrument` and `consent_after_risk_notice`. Comot records the basis you assert and checks it hangs together (`within_nigeria` goes with destination `NG` and only with it). It does **not** judge whether a country is adequate: the Commission had published no list that I could find, and until it does, GAID Schedule 5 is the guide. The other grounds in s.43(1) (contract, public interest, legal claims, vital interests) are left out on purpose, because they rarely fit sharing voice data for research.

### Guardian verification

`guardian_verification` takes `government_id_seen`, `guardian_present`, `facility_record` or `other_documented`. Section 31(3) names government ID as one appropriate mechanism, not the only one, so the list is open to what the field can do. Pick `other_documented` only if your ethics-approved procedure describes the method.

## Readings to confirm with a lawyer

1. **Is voice sensitive?** The Act's definition of sensitive personal data includes health status, and biometric data "for the purpose of uniquely identifying" a person (s.65). Recordings of people talking about their health are health-status data. Voice used only to train speech recognition is not biometric unless it is used to identify speakers. Comot treats all of it as sensitive, which is the cautious reading.
2. **How fast must erasure be?** The Act says "without undue delay" (s.34(2)) and sets no number of days. The 7-day default for deleting copies is easy to defend. The 180-day default for retiring a trained model is the weak point, so set `WithdrawalPolicy` with your ethics board and your lawyer.
3. **Trained models.** GAID Art. 43(2)(b) openly says some AI data, such as synthetic or tokenised data, may not be amenable to the right to be forgotten. That supports Comot telling participants a trained model cannot be undone. It does not clearly permit keeping the weights. Treat it as open.
4. **The research carve-out.** GAID Art. 38(2)(c) lets a controller refuse erasure where it would likely impair or halt research. Comot is stricter than that: the participant can always leave. That is a choice, and your ethics board should make it knowingly. Separately, research on sensitive data needs consent or a law-based ground (Act s.30(1)(i)). The Act has no general research exemption.
5. **Health-sector rules.** The National Health Act 2014 (s.26) protects health records held by health establishments, and secondary sources say it ties disclosure to written consent. If participants are recruited through a health facility or its records, ask whether that sits on top of the Act's allowance for oral consent. The National Code of Health Research Ethics adds ethics-committee approval and consent documentation. Neither was read in full here.
6. **Keeping proof of oral consent.** Comot stores that consent was given, how, with which script and with what teach-back score. It does not store a recording of the consent exchange, which would itself be personal data. If your ethics committee wants one, that is a decision to make explicitly.

## What the deploying organisation must do

These sit outside Comot.

- **DPIA.** Mandatory, vetted and signed by a Commission-accredited DPO, and filed before processing starts, where sensitive data, vulnerable people, health care services or cross-border transfer are involved (GAID Art. 28(3)). Using AI adds a further assessment (Art. 43), and Schedule 6 lists health, age, low education and low digital literacy as vulnerability factors.
- **Registration.** Holding a filing system of personal data on more than 200 people in six months makes an organisation a data controller of major importance (GAID Schedule 7). That means registering, a data protection officer (Act s.32) and an annual compliance audit return.
- **Processors.** A written agreement with every processor (Act s.29), including cloud hosts and annotation vendors.
- **Breach response.** 72 hours to the Commission (Act s.40), and prompt notice to affected people when the risk is high.
- **Penalties.** Fines scale with annual gross revenue, up to 2% in the tier I read (Act ss.48-49).

## Upgrading

Adding these fields changed the consent record, so existing hashes and databases do not carry over. Databases at schema version 1 are refused with a clear error and there is no migration yet, because v0.1 holds no real participants. Exports made before this change do not verify with this version.
