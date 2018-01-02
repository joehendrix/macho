{-# LANGUAGE PatternSynonyms #-}
module Data.MachoPure.Relocations
  ( -- * Relocations
    Relocation(..)
  , RelocationInfo(..)
  , ScatteredRelocationInfo(..)
    -- * Types
  , R_TYPE(..)
    -- ** X86 Relocation types
  , pattern GENERIC_RELOC_VANILLA
  , pattern GENERIC_RELOC_PAIR
  , pattern GENERIC_RELOC_SECTDIFF
  , pattern GENERIC_RELOC_LOCAL_SECTDIFF
  , pattern GENERIC_RELOC_PB_LA_PTR
    -- ** X86_64 Relocation types
  , pattern X86_64_RELOC_UNSIGNED
  , pattern X86_64_RELOC_BRANCH
  , pattern X86_64_RELOC_SIGNED
  , pattern X86_64_RELOC_GOT_LOAD
  , pattern X86_64_RELOC_GOT
  , pattern X86_64_RELOC_SUBTRACTOR
  , pattern X86_64_RELOC_SIGNED_1
  , pattern X86_64_RELOC_SIGNED_2
  , pattern X86_64_RELOC_SIGNED_4
    -- ** ARM Relocation types
  , pattern ARM_RELOC_VANILLA
  , pattern ARM_RELOC_PAIR
  , pattern ARM_RELOC_SECTDIFF
  , pattern ARM_RELOC_LOCAL_SECTDIFF
  , pattern ARM_RELOC_PB_LA_PTR
  , pattern ARM_RELOC_BR24
  , pattern ARM_THUMB_RELOC_BR22
    -- ** PowerPC Relocation types
  , pattern PPC_RELOC_VANILLA
  , pattern PPC_RELOC_PAIR
  , pattern PPC_RELOC_BR14
  , pattern PPC_RELOC_BR24
  , pattern PPC_RELOC_HI16
  , pattern PPC_RELOC_LO16
  , pattern PPC_RELOC_HA16
  , pattern PPC_RELOC_LO14
  , pattern PPC_RELOC_SECTDIFF
  , pattern PPC_RELOC_PB_LA_PTR
  , pattern PPC_RELOC_HI16_SECTDIFF
  , pattern PPC_RELOC_LO16_SECTDIFF
  , pattern PPC_RELOC_HA16_SECTDIFF
  , pattern PPC_RELOC_JBSR
  , pattern PPC_RELOC_LO14_SECTDIFF
  , pattern PPC_RELOC_LOCAL_SECTDIFF
  ) where

import           Data.Int
import           Data.Word

------------------------------------------------------------------------
-- R_TYPE

-- | Platform-specific relocation types.
-- These are four-bit values.
newtype R_TYPE = R_TYPE Word8
  deriving (Eq, Ord, Show)

pattern GENERIC_RELOC_VANILLA :: R_TYPE
pattern GENERIC_RELOC_VANILLA = R_TYPE 0

pattern GENERIC_RELOC_PAIR :: R_TYPE
pattern GENERIC_RELOC_PAIR = R_TYPE 1

pattern GENERIC_RELOC_SECTDIFF :: R_TYPE
pattern GENERIC_RELOC_SECTDIFF = R_TYPE 2

pattern GENERIC_RELOC_LOCAL_SECTDIFF :: R_TYPE
pattern GENERIC_RELOC_LOCAL_SECTDIFF = R_TYPE 3

pattern GENERIC_RELOC_PB_LA_PTR :: R_TYPE
pattern GENERIC_RELOC_PB_LA_PTR = R_TYPE 4

pattern X86_64_RELOC_UNSIGNED :: R_TYPE
pattern X86_64_RELOC_UNSIGNED = R_TYPE 0

pattern X86_64_RELOC_BRANCH :: R_TYPE
pattern X86_64_RELOC_BRANCH = R_TYPE 1

pattern X86_64_RELOC_SIGNED :: R_TYPE
pattern X86_64_RELOC_SIGNED = R_TYPE 2

pattern X86_64_RELOC_GOT_LOAD :: R_TYPE
pattern X86_64_RELOC_GOT_LOAD = R_TYPE 3

pattern X86_64_RELOC_GOT :: R_TYPE
pattern X86_64_RELOC_GOT = R_TYPE 4

pattern X86_64_RELOC_SUBTRACTOR :: R_TYPE
pattern X86_64_RELOC_SUBTRACTOR = R_TYPE 5

pattern X86_64_RELOC_SIGNED_1 :: R_TYPE
pattern X86_64_RELOC_SIGNED_1 = R_TYPE 6

pattern X86_64_RELOC_SIGNED_2 :: R_TYPE
pattern X86_64_RELOC_SIGNED_2 = R_TYPE 7

pattern X86_64_RELOC_SIGNED_4 :: R_TYPE
pattern X86_64_RELOC_SIGNED_4 = R_TYPE 8

pattern ARM_RELOC_VANILLA :: R_TYPE
pattern ARM_RELOC_VANILLA = R_TYPE 0

pattern ARM_RELOC_PAIR :: R_TYPE
pattern ARM_RELOC_PAIR = R_TYPE 1

pattern ARM_RELOC_SECTDIFF :: R_TYPE
pattern ARM_RELOC_SECTDIFF = R_TYPE 2

pattern ARM_RELOC_LOCAL_SECTDIFF :: R_TYPE
pattern ARM_RELOC_LOCAL_SECTDIFF = R_TYPE 3

pattern ARM_RELOC_PB_LA_PTR :: R_TYPE
pattern ARM_RELOC_PB_LA_PTR = R_TYPE 4

pattern ARM_RELOC_BR24 :: R_TYPE
pattern ARM_RELOC_BR24 = R_TYPE 5

pattern ARM_THUMB_RELOC_BR22 :: R_TYPE
pattern ARM_THUMB_RELOC_BR22 = R_TYPE 6


pattern PPC_RELOC_VANILLA :: R_TYPE
pattern PPC_RELOC_VANILLA = R_TYPE 0

pattern PPC_RELOC_PAIR :: R_TYPE
pattern PPC_RELOC_PAIR = R_TYPE 1

pattern PPC_RELOC_BR14 :: R_TYPE
pattern PPC_RELOC_BR14 = R_TYPE 2

pattern PPC_RELOC_BR24 :: R_TYPE
pattern PPC_RELOC_BR24 = R_TYPE 3

pattern PPC_RELOC_HI16 :: R_TYPE
pattern PPC_RELOC_HI16 = R_TYPE 4

pattern PPC_RELOC_LO16 :: R_TYPE
pattern PPC_RELOC_LO16 = R_TYPE 5

pattern PPC_RELOC_HA16 :: R_TYPE
pattern PPC_RELOC_HA16 = R_TYPE 6

pattern PPC_RELOC_LO14 :: R_TYPE
pattern PPC_RELOC_LO14 = R_TYPE 7

pattern PPC_RELOC_SECTDIFF :: R_TYPE
pattern PPC_RELOC_SECTDIFF = R_TYPE 8

pattern PPC_RELOC_PB_LA_PTR :: R_TYPE
pattern PPC_RELOC_PB_LA_PTR = R_TYPE 9

pattern PPC_RELOC_HI16_SECTDIFF :: R_TYPE
pattern PPC_RELOC_HI16_SECTDIFF = R_TYPE 10

pattern PPC_RELOC_LO16_SECTDIFF :: R_TYPE
pattern PPC_RELOC_LO16_SECTDIFF = R_TYPE 11

pattern PPC_RELOC_HA16_SECTDIFF :: R_TYPE
pattern PPC_RELOC_HA16_SECTDIFF = R_TYPE 12

pattern PPC_RELOC_JBSR :: R_TYPE
pattern PPC_RELOC_JBSR = R_TYPE 13

pattern PPC_RELOC_LO14_SECTDIFF :: R_TYPE
pattern PPC_RELOC_LO14_SECTDIFF = R_TYPE 14

pattern PPC_RELOC_LOCAL_SECTDIFF :: R_TYPE
pattern PPC_RELOC_LOCAL_SECTDIFF = R_TYPE 15

------------------------------------------------------------------------
-- RelocationInfo

-- | non-scattered relocation information.
data RelocationInfo =
   RelocationInfo
        { ri_address   :: Int32  -- ^ offset from start of section to place to be relocated
        , ri_symbolnum :: Word32 -- ^ index into symbol or section table
        , ri_pcrel     :: Bool   -- ^ indicates if the item to be relocated is part of an instruction containing PC-relative addressing
        , ri_length    :: Word32 -- ^ length of item containing address to be relocated (literal form (4) instead of power of two (2))
        , ri_extern    :: Bool   -- ^ indicates whether symbolnum is an index into the symbol table (True) or section table (False)
        , ri_type      :: R_TYPE -- ^ relocation type
        }
    deriving (Show, Eq)

data ScatteredRelocationInfo =
  ScatteredRelocationInfo
  { srs_pcrel   :: Bool   -- ^ indicates if the item to be relocated is part of an instruction containing PC-relative addressing
  , srs_length  :: Word32 -- ^ length of item containing address to be relocated (literal form (4) instead of power of two (2))
  , srs_type    :: R_TYPE -- ^ relocation type
  , srs_address :: Word32 -- ^ offset from start of section to place to be relocated
  , srs_value   :: Int32  -- ^ address of the relocatable expression for the item in the file that needs to be updated if the address is changed
  }
  deriving (Show, Eq)

data Relocation
    = Unscattered !RelocationInfo
    | Scattered !ScatteredRelocationInfo
    deriving (Show, Eq)
