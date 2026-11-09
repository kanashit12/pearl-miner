# pearl-miner

Miner PoW untuk PEARL v2 (PearlMiningV4, BSC). Mencari nonce agar
`keccak256(abi.encode(puzzleSeed, nonce)) <= target`, di-shard ke banyak
runner GitHub Actions lewat workflow `mine.yml` (workflow_dispatch).

- `miner.c` — miner keccak256 multithread (start/step untuk sharding).
- Koordinator (di VM agen, bukan di repo ini) membaca seed/target/round dari
  kontrak, men-dispatch workflow, mengambil nonce dari artifact, lalu
  mengirim `mine(...)` lewat Binance Agentic Wallet.

Tidak ada rahasia apa pun di repo ini: seed dan target adalah nilai publik
dari kontrak on-chain.
