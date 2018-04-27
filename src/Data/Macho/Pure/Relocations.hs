{-# LANGUAGE PatternSynonyms #-}
module Data.Macho.Pure.Relocations
  ( -- * Relocations
    Relocation(..)
  , getRelocations
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

import Data.Bits
import Data.Int
import Data.Word
import Numeric

import Data.Macho.Pure.Decoder
import Data.Macho.Pure.Header

------------------------------------------------------------------------
-- R_TYPE

-- | Platform-specific relocation types.
-- These are four-bit values.
newtype R_TYPE = R_TYPE Word8
  deriving (Eq, Ord)

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

instance CPUSpecific R_TYPE where
  ppCPUSpecific _ (R_TYPE x) = show x

------------------------------------------------------------------------
-- RelocationInfo

-- | non-scattered relocation information.
data RelocationInfo =
   RelocationInfo
        { ri_address   :: !Word32  -- ^ offset from start of section to place to be relocated
        , ri_symbolnum :: !Word32 -- ^ index into symbol or section table
        , ri_pcrel     :: !Bool   -- ^ indicates if the item to be relocated is part of an instruction containing PC-relative addressing
        , ri_length    :: !Word32 -- ^ length of item containing address to be relocated (literal form (4) instead of power of two (2))
        , ri_extern    :: !Bool   -- ^ indicates whether symbolnum is an index into the symbol table (True) or section table (False)
        , ri_type      :: !R_TYPE -- ^ relocation type
        }
    deriving (Eq)

instance CPUSpecific RelocationInfo where
  ppCPUSpecific cpu ri
    =  "addr: 0x" ++ showHex (ri_address ri) ""
    ++ ", sidx: " ++ show (ri_symbolnum ri)
    ++ ", pcrel: " ++ (if ri_pcrel ri then "1" else "0")
    ++ ", len: " ++ show (ri_length ri)
    ++ ", ext: " ++ (if ri_extern ri then "1" else "0")
    ++ ", type: " ++ ppCPUSpecific cpu (ri_type ri)

data ScatteredRelocationInfo =
  ScatteredRelocationInfo
  { srs_pcrel   :: Bool   -- ^ indicates if the item to be relocated is part of an instruction containing PC-relative addressing
  , srs_length  :: Word32 -- ^ length of item containing address to be relocated (literal form (4) instead of power of two (2))
  , srs_type    :: R_TYPE -- ^ relocation type
  , srs_address :: Word32 -- ^ offset from start of section to place to be relocated
  , srs_value   :: Int32  -- ^ address of the relocatable expression for the item in the file that needs to be updated if the address is changed
  }
  deriving (Eq)

instance CPUSpecific ScatteredRelocationInfo where
  ppCPUSpecific cpu ri
    =  "addr: 0x" ++ showHex (srs_address ri) ""
    ++ ", val: " ++ show (srs_value ri)
    ++ ", pcrel: " ++ (if srs_pcrel ri then "1" else "0")
    ++ ", len: " ++ show (srs_length ri)
    ++ ", type: " ++ ppCPUSpecific cpu (srs_type ri)

data Relocation
    = Unscattered !RelocationInfo
    | Scattered !ScatteredRelocationInfo
    deriving (Eq)

instance CPUSpecific Relocation where
  ppCPUSpecific cpu (Unscattered ri) = ppCPUSpecific cpu ri
  ppCPUSpecific cpu (Scattered sri) = ppCPUSpecific cpu sri

-- | Return size of a relocation entry.
relocationSize :: Word32
relocationSize = 8

getRel :: Decoder Relocation
getRel = do
  r_address <- getWord32
  r_value   <- getWord32
  if (r_address .&. 0x80000000) /= 0 then do
    rs_pcrel   <- (1 ==) <$> bitfield 1 1 r_address
    rs_length  <- (2 ^) <$> bitfield 2 2 r_address
    rs_type    <- R_TYPE . fromIntegral <$> bitfield 4 4 r_address
    rs_address <- bitfield 8 24 r_address
    let info = ScatteredRelocationInfo
            { srs_pcrel = rs_pcrel
            , srs_length = rs_length
            , srs_type = rs_type
            , srs_address = rs_address
            , srs_value = fromIntegral r_value
            }
    return $ Scattered info
   else do
    symbolnum <- bitfield 0 24 r_value
    pcrel  <- bitfield 24 1 r_value
    len    <- bitfield 25 2 r_value
    extern <- bitfield 27 1 r_value
    tp     <- R_TYPE . fromIntegral <$> bitfield 28 4 r_value
    let info = RelocationInfo { ri_address = r_address
                              , ri_symbolnum = symbolnum
                              , ri_pcrel = pcrel == 1
                              , ri_length = 2 ^ len
                              , ri_extern = extern == 1
                              , ri_type = tp
                              }
    return $ Unscattered info

getRelocations :: MachoFile -> FileOffset -> Word32 -> Maybe [Relocation]
getRelocations mfile off cnt = getTable mfile off cnt relocationSize getRel
