# ΛMNOS Browser — Protection domain-list attribution

The 63,356-domain Candidate v2 was derived by deterministic normalization, validation, filtering and deduplication of four pinned third-party snapshots. It has NOT yet been HSM-signed or activated as a production feed.

- BigDargon / hostsVN adult-VN (MIT), source commit ffd066115880f98f590640ae55e544fbfc46d9b5; https://github.com/bigdargon/hostsVN
- Sinfonietta / pornography-hosts (MIT), source commit 46f3097d7bcfc9eea323fe365074dfd771d0d17c; https://github.com/Sinfonietta/hostfiles
- Sinfonietta / snuff-hosts (MIT), same pinned source commit; https://github.com/Sinfonietta/hostfiles
- Tiuxo / pornography hosts (CC BY 4.0), source commit b950765effd7808e90fda888b23540689ed46766; https://github.com/tiuxo/hosts

Modification indication: AMNOS normalizes source hosts files to a sorted domain-policy JSON, ignores invalid entries, deduplicates across lists and rejects domains in conflict with reviewed controls. The combined output may differ from the upstream sources. The upstream maintainers have not endorsed AMNOS.

Exact pinned upstream license texts are in compliance/licenses/, including CC BY 4.0 and the two distinct MIT grants. Original license and source links are in THIRD_PARTY_NOTICES.md.

The Public Suffix List is used only during build-time validation, not bundled in the deployed blocklist. Its MPL 2.0 license text is retained in compliance/licenses/ for audit.

This repository contains no private keys, service-account credentials, user data or browsing histories.

ΛMNOS
Made with purpose.
