-- |
-- Module      : Crypto.PubKey.ECC.DH.P256
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
-- Elliptic curve Diffie Hellman
--
module Crypto.PubKey.ECC.DH.P256
    (
      PublicPoint
    , PrivateNumber
    , SharedKey(..)
    , generatePrivate
    , calculatePublic
    , getShared
    ) where

import Crypto.Number.Generate (generateMax)
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.PubKey.DH (SharedKey(..))
import Crypto.PubKey.ECC.P256
import Crypto.Random.Types
import Crypto.Error (CryptoFailable(..))

type PublicPoint = Point
type PrivateNumber = Integer

-- | Generating a private number d.
generatePrivate :: MonadRandom m => m PrivateNumber
generatePrivate = scalarToInteger <$> scalarGenerate

-- | Generating a public point Q.
calculatePublic :: PrivateNumber -> PublicPoint
calculatePublic d = toPoint d'
  where
    CryptoPassed d' = scalarFromInteger d

-- | Generating a shared key using our private number and
--   the other party public point.
getShared :: PrivateNumber -> PublicPoint -> SharedKey
getShared db qa = SharedKey $ i2ospOf_ 32 x
  where
    CryptoPassed db' = scalarFromInteger db
    (x, _) = pointToIntegers $ pointMul db' qa
