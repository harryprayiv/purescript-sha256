module Test.Crypto.SHA256.Bench where

import Prelude

import Crypto.SHA256 (SHA2(..), hash, hmacSha256Buf)
import Data.Array as A
import Data.Int (toNumber)
import Effect (Effect)
import Effect.Console (log)
import Node.Buffer as Buffer
import Node.Buffer (Buffer)
import Test.Crypto.SHA256 as SHA256Tests

-------------------------------------------------------------------------------
-- FFI
-------------------------------------------------------------------------------

foreign import performanceNow :: Effect Number

-- | Defer a pure computation into Effect so it is re-evaluated each call.
foreign import defer :: forall a. (Unit -> a) -> Effect a

-------------------------------------------------------------------------------
-- Timing Helpers
-------------------------------------------------------------------------------

-- | Run an action N times and return total elapsed milliseconds.
timeN :: Int -> Effect Unit -> Effect Number
timeN n action = do
  t0 <- performanceNow
  go 0
  t1 <- performanceNow
  pure (t1 - t0)
  where
  go i
    | i >= n = pure unit
    | otherwise = action *> go (i + 1)

-- | Format a benchmark result line.
report :: String -> Int -> Int -> Number -> Effect Unit
report label iterations inputBytes ms = do
  let
    throughputMBs =
      if ms > 0.0 then
        (toNumber (iterations * inputBytes) / 1048576.0) / (ms / 1000.0)
      else 0.0
    opsPerSec =
      if ms > 0.0 then toNumber iterations / (ms / 1000.0)
      else 0.0
  log $ "  " <> label
    <> "  " <> show iterations <> " iters"
    <> "  " <> show ms <> " ms"
    <> "  " <> show opsPerSec <> " ops/s"
    <> "  " <> show throughputMBs <> " MB/s"

-------------------------------------------------------------------------------
-- Input Generators
-------------------------------------------------------------------------------

-- | Create a Buffer of N zero bytes.
zeroBuffer :: Int -> Effect Buffer
zeroBuffer n = Buffer.fromArray (A.replicate n 0)

-------------------------------------------------------------------------------
-- Benchmarks
-------------------------------------------------------------------------------

benchSuite :: Effect Unit
benchSuite = do
  log "═══════════════════════════════════════════════════════════"
  log "  SHA-256 Benchmarks"
  log "═══════════════════════════════════════════════════════════"

  log "\n── SHA-256 (small inputs) ─────────────────────────────"
  let iters = 500

  do
    buf <- zeroBuffer 0
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 buf)
    report "empty (0 B)" iters 0 ms

  do
    buf <- zeroBuffer 32
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 buf)
    report "32 B       " iters 32 ms

  do
    buf <- zeroBuffer 55
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 buf)
    report "55 B (1blk)" iters 55 ms

  do
    buf <- zeroBuffer 64
    ms <- timeN iters (void $ defer \_ -> hash SHA2_256 buf)
    report "64 B (2blk)" iters 64 ms

  log "\n── SHA-256 (multi-block) ──────────────────────────────"
  let itersM = 100

  do
    buf <- zeroBuffer 512
    ms <- timeN itersM (void $ defer \_ -> hash SHA2_256 buf)
    report "512 B      " itersM 512 ms

  do
    buf <- zeroBuffer 1024
    ms <- timeN itersM (void $ defer \_ -> hash SHA2_256 buf)
    report "1 KiB      " itersM 1024 ms

  do
    buf <- zeroBuffer 4096
    ms <- timeN itersM (void $ defer \_ -> hash SHA2_256 buf)
    report "4 KiB      " itersM 4096 ms

  log "\n── SHA-256 (large inputs) ─────────────────────────────"
  let itersL = 10

  do
    buf <- zeroBuffer 65536
    ms <- timeN itersL (void $ defer \_ -> hash SHA2_256 buf)
    report "64 KiB     " itersL 65536 ms

  do
    buf <- zeroBuffer 1048576
    ms <- timeN itersL (void $ defer \_ -> hash SHA2_256 buf)
    report "1 MiB      " itersL 1048576 ms

  log "\n── SHA-224 vs SHA-256 (256 B input) ───────────────────"
  let itersV = 200

  do
    buf <- zeroBuffer 256
    ms224 <- timeN itersV (void $ defer \_ -> hash SHA2_224 buf)
    report "SHA-224    " itersV 256 ms224
    ms256 <- timeN itersV (void $ defer \_ -> hash SHA2_256 buf)
    report "SHA-256    " itersV 256 ms256

  log "\n── HMAC-SHA256 ───────────────────────────────────────"
  let itersH = 200

  do
    key <- zeroBuffer 32
    msg <- zeroBuffer 32
    ms <- timeN itersH (void $ defer \_ -> hmacSha256Buf key msg)
    report "32 B msg   " itersH 32 ms

  do
    key <- zeroBuffer 32
    msg <- zeroBuffer 256
    ms <- timeN itersH (void $ defer \_ -> hmacSha256Buf key msg)
    report "256 B msg  " itersH 256 ms

  do
    key <- zeroBuffer 32
    msg <- zeroBuffer 1024
    ms <- timeN itersH (void $ defer \_ -> hmacSha256Buf key msg)
    report "1 KiB msg  " itersH 1024 ms

  log "\n═══════════════════════════════════════════════════════════"
  log "  Done."
  log "═══════════════════════════════════════════════════════════"


main :: Effect Unit
main = do
  SHA256Tests.main
  log ""
  benchSuite