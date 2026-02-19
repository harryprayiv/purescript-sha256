module Test.Main where

import Prelude

import Data.Array as A
import Effect (Effect)
import Effect.Console (log)
import Test.Crypto.SHA256 as SHA256Tests
import Test.Crypto.SHA256.Bench as Bench

foreign import argv :: Array String

main :: Effect Unit
main = do
  let args = argv
  SHA256Tests.main
  if A.elem "--bench" args then do
    log ""
    Bench.benchSuite
  else
    log "\n(run with --bench to include benchmarks)"