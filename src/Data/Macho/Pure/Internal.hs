{-| Provides a pretty-printing utility for other modules. -}
module Data.Macho.Pure.Internal
  ( showPadHex
  ) where

import Data.Bits
import Numeric (showHex)

-- | Show a finite bits in hex with full bitwidth.
showPadHex :: (FiniteBits a, Integral a, Show a) => a -> String
showPadHex a = "0x" ++ replicate (c - length s) '0' ++ s
  where c = finiteBitSize a
        s = showHex a ""
