module Test.Main where

import Prelude
import Effect (Effect)
import Effect.Console (log)
import Test.SHA256 as SHA256Tests
import Test.SHA256.Bench as Bench

foreign import hasBenchFlag :: Boolean

main :: Effect Unit
main = do
  SHA256Tests.main
  when hasBenchFlag do
    log ""
    Bench.benchSuite