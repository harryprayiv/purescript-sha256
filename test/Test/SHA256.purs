module Test.SHA256 where

import Prelude

import Crypto.SHA256 (SHA2(..), hash, toString, fromHex)
import Data.Array as A
import Data.Foldable (for_)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Console (log)

type TestCase =
  { name     :: String
  , result   :: String
  , expected :: String
  }

runTests :: Array TestCase -> Effect Unit
runTests tests = do
  let
    results = map
      ( \t ->
          { name: t.name
          , passed: t.result == t.expected
          , result: t.result
          , expected: t.expected
          }
      )
      tests
    passed = A.length (A.filter _.passed results)
    failed = A.length (A.filter (not <<< _.passed) results)

  for_ results \r ->
    if r.passed then log ("  ✓ " <> r.name)
    else do
      log ("  ✗ " <> r.name)
      log ("    expected: " <> r.expected)
      log ("    got:      " <> r.result)

  log ""
  log (show passed <> " passed, " <> show failed <> " failed")

-- | Hash a string, return hex.
hashStr :: SHA2 -> String -> String
hashStr variant = toString <<< hash variant

main :: Effect Unit
main = do
  log "SHA-2 (FIPS 180-4) Test Suite — purescm / Chez Scheme backend\n"
  runTests
    -- SHA-256: NIST FIPS 180-4 §B.1 — empty
    [ { name: "SHA-256(\"\")"
      , result: hashStr SHA2_256 ""
      , expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }

    -- SHA-256: NIST FIPS 180-4 §B.1 — "abc"
    , { name: "SHA-256(\"abc\")"
      , result: hashStr SHA2_256 "abc"
      , expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      }

    -- SHA-256: NIST FIPS 180-4 §B.2 — two-block (56 bytes)
    , { name: "SHA-256(\"abcdbcde...nopq\")"
      , result: hashStr SHA2_256 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      , expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
      }

    -- SHA-256: NIST FIPS 180-4 §B.3 — 112 bytes
    , { name: "SHA-256(\"abcdefgh...nopqrstu\")"
      , result: hashStr SHA2_256 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
      , expected: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
      }

    -- SHA-256: 1 million 'a's
    , { name: "SHA-256(1M × 0x61)"
      , result: toString (hash SHA2_256 (A.replicate 1000000 0x61))
      , expected: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
      }

    -- SHA-256: single byte
    , { name: "SHA-256(\"a\")"
      , result: hashStr SHA2_256 "a"
      , expected: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
      }

    -- SHA-256: 55 bytes — exactly one block after padding (55+1+8=64)
    , { name: "SHA-256(55 × 0x61, 1 block)"
      , result: toString (hash SHA2_256 (A.replicate 55 0x61))
      , expected: "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
      }

    -- SHA-256: 56 bytes — boundary, needs second block for length
    , { name: "SHA-256(56 × 0x61, 2 blocks)"
      , result: toString (hash SHA2_256 (A.replicate 56 0x61))
      , expected: "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
      }

    -- SHA-256: raw byte array input
    , { name: "SHA-256([0xde,0xad,0xbe,0xef])"
      , result: toString (hash SHA2_256 [0xde, 0xad, 0xbe, 0xef])
      , expected: "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953"
      }

    -- SHA-224: NIST FIPS 180-4 — empty
    , { name: "SHA-224(\"\")"
      , result: hashStr SHA2_224 ""
      , expected: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
      }

    -- SHA-224: NIST FIPS 180-4 — "abc"
    , { name: "SHA-224(\"abc\")"
      , result: hashStr SHA2_224 "abc"
      , expected: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
      }

    -- SHA-224: two-block
    , { name: "SHA-224(\"abcdbcde...nopq\")"
      , result: hashStr SHA2_224 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      , expected: "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
      }

    -- Digest Eq instance
    , { name: "Digest Eq (same input)"
      , result: show (hash SHA2_256 "abc" == hash SHA2_256 "abc")
      , expected: "true"
      }
    , { name: "Digest Eq (different input)"
      , result: show (hash SHA2_256 "abc" == hash SHA2_256 "def")
      , expected: "false"
      }

    -- fromHex roundtrip
    , { name: "fromHex roundtrip"
      , result: show (map toString (fromHex (toString (hash SHA2_256 "abc"))))
      , expected: show (Just (toString (hash SHA2_256 "abc")))
      }
    ]