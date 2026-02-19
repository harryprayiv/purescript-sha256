-- | SHA-2 (FIPS 180-4) cryptographic hash functions: SHA-256 and SHA-224,
-- | plus HMAC-SHA256 (RFC 2104).
-- |
-- | Optimized JavaScript FFI implementation using Buffer-native operations.
-- | All hot paths work directly on Node Buffers with zero intermediate
-- | Array conversions.
module Crypto.SHA256
  ( SHA2(..)
  , Digest
  , class Hashable
  , hash
  , sha256
  , sha224
  , hmacSha256
  , hmacSha256Buf
  , exportToBuffer
  , importFromBuffer
  , toString
  , fromHex
  ) where

import Prelude

import Data.Maybe (Maybe(..))
import Node.Buffer (Buffer)

-------------------------------------------------------------------------------
-- FFI
-------------------------------------------------------------------------------

foreign import sha256Buf        :: Buffer -> Buffer
foreign import sha224Buf        :: Buffer -> Buffer
foreign import hmacSha256Impl   :: Buffer -> Buffer -> Buffer
foreign import bufferToHex      :: Buffer -> String
foreign import bufferFromHex    :: (Buffer -> Maybe Buffer) -> (forall a. Maybe a) -> String -> Maybe Buffer
foreign import stringToUtf8Buffer :: String -> Buffer
foreign import eqBuffer         :: Buffer -> Buffer -> Boolean

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | SHA-2 hash function variants.
data SHA2 = SHA2_256 | SHA2_224

-- | The output of a SHA-2 hash function.
newtype Digest = Digest Buffer

instance eqDigest :: Eq Digest where
  eq (Digest a) (Digest b) = eqBuffer a b

instance showDigest :: Show Digest where
  show d = "(Digest " <> toString d <> ")"

-------------------------------------------------------------------------------
-- Hashable
-------------------------------------------------------------------------------

-- | Types that can be hashed with a SHA-2 function.
class Hashable a where
  hash :: SHA2 -> a -> Digest

instance hashableString :: Hashable String where
  hash variant value = hashBuffer variant (stringToUtf8Buffer value)

instance hashableBuffer :: Hashable Buffer where
  hash = hashBuffer

hashBuffer :: SHA2 -> Buffer -> Digest
hashBuffer SHA2_256 buf = Digest (sha256Buf buf)
hashBuffer SHA2_224 buf = Digest (sha224Buf buf)

-------------------------------------------------------------------------------
-- Convenience Hash Functions
-------------------------------------------------------------------------------

-- | SHA-256: 256-bit (32-byte) digest.
sha256 :: forall a. Hashable a => a -> Digest
sha256 = hash SHA2_256

-- | SHA-224: 224-bit (28-byte) digest.
sha224 :: forall a. Hashable a => a -> Digest
sha224 = hash SHA2_224

-------------------------------------------------------------------------------
-- HMAC-SHA256 (RFC 2104 / RFC 4231)
-------------------------------------------------------------------------------

-- | HMAC-SHA256 with String key and String message.
hmacSha256 :: String -> String -> Digest
hmacSha256 key msg =
  Digest (hmacSha256Impl (stringToUtf8Buffer key) (stringToUtf8Buffer msg))

-- | HMAC-SHA256 operating directly on Buffers (zero-copy).
hmacSha256Buf :: Buffer -> Buffer -> Digest
hmacSha256Buf key msg =
  Digest (hmacSha256Impl key msg)

-------------------------------------------------------------------------------
-- Serialization
-------------------------------------------------------------------------------

-- | Extract the raw buffer from a digest.
exportToBuffer :: Digest -> Buffer
exportToBuffer (Digest buf) = buf

-- | Wrap a buffer as a digest. No validation is performed on length.
importFromBuffer :: Buffer -> Maybe Digest
importFromBuffer = Just <<< Digest

-- | Hex-encode a digest.
toString :: Digest -> String
toString (Digest buf) = bufferToHex buf

-- | Decode a hex string to a digest.
fromHex :: String -> Maybe Digest
fromHex = map Digest <<< bufferFromHex Just Nothing