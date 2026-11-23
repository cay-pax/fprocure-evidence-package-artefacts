# Coston2 references (Flare public test network, chain ID 114)

## Baseline run, first contract version (July 2026)

| Item | Reference |
|---|---|
| F-Procure contract | 0xc181573E4C707D8eB5DF021aFfE19ca896c6d5fc |
| Escrow contract | 0xE8bc020DCf1df450480de0833f00D4a2E597F1Fe |
| Evidence anchor (event-only) | 0x2286bA4a4cED6E8fD279D57F7E3075CFB8B6dd83 |
| Create tender (contract tender 20) | 0x0194a3ce9244ea9e6ddd4b3db70875042c72828e6ee30889541bb73d907fe7c6 |
| Commit bid | 0xca0ee07f013518ea7fbd6ae839d0335d98d99c76ca360d5f398f260a1ddd2c78 |
| Close commit phase | 0x92c2c8d7cc9945086d3f49ebcd92f7faf8d0c415ea151f15ad4a8d8a538a5d38 |
| Reveal bid | 0x428c13fae2a9eac0fd1bf8c1defdc39ff250b720096caa56752ac0cb6980fd68 |
| Close reveal phase | 0x08218de9605a29c68a4aa50d2b0ba451776316f4fccc9f443ae9d72f565f3f9b |
| Evaluate | 0xdba16eda38652c0e09008c2c8397d9ebc9e28a437192057ead57f6d5661b375d |
| Award | 0x080e163f601e490cdbb19e33054574e860199905a7516cde9109e6b10a57befc |
| Fund escrow | 0x730eca844c6cf91705c88a721de45253742b2fe3cc1911801e6bba2795a8b607 |
| Release escrow | 0x72db8412086293a9b5e1f6486d1ecd9461d0b16cdf9014446a71c52c4144c0bb |
| Anchor evidence (block 32,651,232) | 0xd14176d93462b1c623a02dde43f5163aa94b6786d560f07d2685591ffb68dd59 |
| Anchored package digest | 0x294ec9f28a1f974dea5f0609c0b3c598f9d2d206d0d569576bdac6633fc4ba41 |
| Submitting account | 0xa0a31cff6aa76d110675fd81d8d571d7a9c9f597 |

Every transaction was re-checked read-only on 22 November 2026 (status 1). The exported archive of this package is not included here.

## Research deployment, second contract version (evaluation pending)

| Item | Reference |
|---|---|
| F-Procure contract | 0xa00C4117D8061752970070e06Ab83670A497f4Fa |
| FTSO price source | 0x6950bbD9B0213D3747D31708c9151e6b614442E9 |
| Escrow contract | 0x2790568A6c732EeBfF896182041C5A43Ff1008F7 |
| Evidence anchor (tender-bound) | 0x06f11C9aE17f9891C771DEEEb795D897D8329a45 |
| Owner (dedicated test account) | 0x33d87b3ac5460bd9dad7ef888da21e01d0315c4e |
| Deployment blocks | 38,181,401–38,181,407 |

## Package-to-anchor experiment, tender-bound anchor (ProofRails, 23 November 2026)

| Item | Reference |
|---|---|
| Evidence anchor (tender-bound, flattened copy) | 0x19E5612b9588CE884893373398a4b2C5Aa05a5f1 |
| Deployment transaction | 0xb7cad7d8e22cd94d1b126aa1034e8e2be6823b0f24b686367ea9a2d89b111524 |
| Anchor transaction (block 38,199,816) | 0x1e87973c134c00d4e6aa48fea5ce7d10f5f0d0bd1879caa15e8e50cf5d0fe132 |
| Tender reference | 0xf02f872f14bb22ac3d172857e89e05eea63e8958f287d7b2c9419be1bc8cf441 |
| Package version | 1 |
| Anchored package digest (`tep.zip`) | 0x6dc5bacdaae60f57b593e9671925bc366894be19ac83b184ebe542efc89d0cbb |
| Rewritten copy digest (`altered.zip`, not anchored) | 0x7eceaf451842c1c653eee50d12a0e0daf947869d6e4679a4b75f04fea60d70e6 |
| Submitting and owner account (single-use test account) | 0xaE229CE18e0fa28a5378675fE216F4Df7b4cfB69 |

The files are in [package-to-anchor-2026-11-23/](package-to-anchor-2026-11-23/). The package is minimal and synthetic: it was assembled for the experiment, not exported by F-Procure, and has no bids or lifecycle events. `report.json` and `proofrails_verifier_report.json` are ProofRails' deployment report and its JavaScript verifier's output. `verify_tep_*.json` are the outputs of `verifier/verify_tep.py`. The package passes steps 1–11, and the rewritten copy fails steps 10 and 11. Steps 12 and 13 are skipped. To re-run:

```
python3 verifier/verify_tep.py coston2/package-to-anchor-2026-11-23/tep.zip \
  --rpc https://coston2-api.flare.network/ext/C/rpc --chain-id 114 \
  --contract 0x19E5612b9588CE884893373398a4b2C5Aa05a5f1 \
  --tx 0x1e87973c134c00d4e6aa48fea5ce7d10f5f0d0bd1879caa15e8e50cf5d0fe132
```
