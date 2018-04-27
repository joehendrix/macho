{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
module Data.Macho.Pure.Commands.Section
  ( -- * Segment name
    SegmentName
  , getSegmentName
    -- * Section
  , MachoSection(..)
  , secType
  , getSectionRelocs
  , SectionName
  , getSectionName
  , Align(..)
    -- ** SectionType
  , SectionType(..)
  , pattern S_REGULAR
  , pattern S_ZEROFILL
  , pattern S_CSTRING_LITERALS
  , pattern S_4BYTE_LITERALS
  , pattern S_8BYTE_LITERALS
  , pattern S_LITERAL_POINTERS
  , pattern S_NON_LAZY_SYMBOL_POINTERS
  , pattern S_LAZY_SYMBOL_POINTERS
  , pattern S_SYMBOL_STUBS
  , pattern S_MOD_INIT_FUNC_POINTERS
  , pattern S_MOD_TERM_FUNC_POINTERS
  , pattern S_COALESCED
  , pattern S_GB_ZEROFILL
  , pattern S_INTERPOSING
  , pattern S_16BYTE_LITERALS
  , pattern S_DTRACE_DOF
  , pattern S_LAZY_DYLIB_SYMBOL_POINTERS
    -- ** Section flags
  , S_ATTR(..)
  , pattern S_ATTR_PURE_INSTRUCTIONS
  , pattern S_ATTR_NO_TOC
  , pattern S_ATTR_STRIP_STATIC_SYMS
  , pattern S_ATTR_NO_DEAD_STRIP
  , pattern S_ATTR_LIVE_SUPPORT
  , pattern S_ATTR_SELF_MODIFYING_CODE
  , pattern S_ATTR_DEBUG
  , pattern S_ATTR_SOME_INSTRUCTIONS
  , pattern S_ATTR_EXT_RELOC
  , pattern S_ATTR_LOC_RELOC
  ) where

import           Data.Binary.Get hiding (Decoder)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import           Data.Monoid
import           Data.String
import           Data.Word
import           Numeric (showHex)

import           Data.Macho.Pure.Decoder
import           Data.Macho.Pure.Relocations


showPadHex :: (FiniteBits a, Integral a, Show a) => a -> String
showPadHex a = "0x" ++ replicate (c - length s) '0' ++ s
  where c = finiteBitSize a
        s = showHex a ""

------------------------------------------------------------------------
-- SectionName

newtype SectionName = SectionName B.ByteString
  deriving (Eq, Ord)

getSectionName :: Get SectionName
getSectionName = SectionName <$> getByteString 16

instance IsString SectionName where
  fromString s
      | B.length b > 16 = error "Section names are at most 16 bytes."
      | otherwise = SectionName (b <> B.replicate (16 - B.length b) 0)
    where b = C.pack s

instance Show SectionName where
  show (SectionName b) = C.unpack b

------------------------------------------------------------------------
-- SegmentName

-- | A 16-character segment name.
newtype SegmentName = SegmentName B.ByteString
  deriving (Eq, Ord)

getSegmentName :: Get SegmentName
getSegmentName = SegmentName <$> getByteString 16

instance IsString SegmentName where
  fromString s
      | B.length b > 16 = error "Segment names are at most 16 bytes."
      | otherwise = SegmentName (b <> B.replicate (16 - B.length b) 0)
    where b = C.pack s

instance Show SegmentName where
  show (SegmentName b) = C.unpack b

------------------------------------------------------------------------
-- S_ATTR

-- | Section attributes (this contains the full 32-bit flags, and
-- the low 8-bits are for the type.
newtype S_ATTR = S_ATTR { secAttrValue :: Word32 }
  deriving (Eq, Bits, Num)

-- | Return the type bits from the attribute.
secAttrType :: S_ATTR -> SectionType
secAttrType = SectionType . fromIntegral . secAttrValue

instance Show S_ATTR where
  show (S_ATTR x) = showPadHex x

pattern S_ATTR_PURE_INSTRUCTIONS :: S_ATTR
pattern S_ATTR_PURE_INSTRUCTIONS = S_ATTR 0x80000000
-- ^ section contains only true machine instructions

pattern S_ATTR_NO_TOC :: S_ATTR
pattern S_ATTR_NO_TOC = S_ATTR 0x40000000
-- ^ setion contains coalesced symbols that are not to be in a ranlib table of contents

pattern S_ATTR_STRIP_STATIC_SYMS :: S_ATTR
pattern S_ATTR_STRIP_STATIC_SYMS = S_ATTR 0x20000000
-- ^ ok to strip static symbols in this section in files with the MH_DYLDLINK flag

pattern S_ATTR_NO_DEAD_STRIP :: S_ATTR
pattern S_ATTR_NO_DEAD_STRIP = S_ATTR 0x10000000
-- ^ no dead stripping

pattern S_ATTR_LIVE_SUPPORT :: S_ATTR
pattern S_ATTR_LIVE_SUPPORT = S_ATTR  0x08000000
-- ^ blocks are live if they reference live blocks

pattern S_ATTR_SELF_MODIFYING_CODE :: S_ATTR
pattern S_ATTR_SELF_MODIFYING_CODE = S_ATTR 0x04000000
-- ^ used with i386 code stubs written on by dyld

pattern S_ATTR_DEBUG :: S_ATTR
pattern S_ATTR_DEBUG = S_ATTR 0x02000000
-- ^ a debug section

pattern S_ATTR_SOME_INSTRUCTIONS :: S_ATTR
pattern S_ATTR_SOME_INSTRUCTIONS = S_ATTR 0x00000400
-- ^ section contains soem machine instructions

pattern S_ATTR_EXT_RELOC :: S_ATTR
pattern S_ATTR_EXT_RELOC = S_ATTR 0x00000200
-- ^ section has external relocation entries

pattern S_ATTR_LOC_RELOC :: S_ATTR
pattern S_ATTR_LOC_RELOC = S_ATTR 0x00000100
-- ^ section has local relocation entries

------------------------------------------------------------------------
-- Align

-- | An alignment field
newtype Align = Align Word32
  deriving (Eq)

instance Show Align where
  show (Align w) = "2^" ++ show w ++ "(" ++ show (2^w :: Integer) ++ ")"

------------------------------------------------------------------------
-- MachoSection

-- | Section and Section_64 entries
data MachoSection w = MachoSection
    { secSectname :: !SectionName
      -- ^ name of section
    , secSegname  :: !SegmentName -- ^ name of segment that should own this section
    , secAddr     :: !w           -- ^ virtual memoy address for section
    , secSize     :: !w           -- ^ size of section

    , secOffset   :: !Word32
    , secAlign    :: !Align
      -- ^ alignment required by section
    , secReloff    :: !FileOffset -- ^ Offset to relocations for section
    , secNReloc    :: !Word32     -- ^ Number of relocations for section
    , secFlags     :: !S_ATTR        -- ^ attributes of section
    , secReserved1 :: !Word32 -- ^ First reserved value
    , secReserved2 :: !w      -- ^ Second reserved value
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- SectionType

-- | A section type
newtype SectionType = SectionType Word8
  deriving (Eq,Show)

pattern S_REGULAR :: SectionType
pattern S_REGULAR = SectionType 0x00
-- ^ regular section

pattern S_ZEROFILL :: SectionType
pattern S_ZEROFILL = SectionType 0x01
-- ^ zero fill on demand section

pattern S_CSTRING_LITERALS :: SectionType
pattern S_CSTRING_LITERALS = SectionType 0x02
-- ^ section with only literal C strings

pattern S_4BYTE_LITERALS :: SectionType
pattern S_4BYTE_LITERALS = SectionType 0x03
-- ^ section with only 4 byte literals

pattern S_8BYTE_LITERALS :: SectionType
pattern S_8BYTE_LITERALS = SectionType 0x04
-- ^ section with only 8 byte literals

pattern S_LITERAL_POINTERS :: SectionType
pattern S_LITERAL_POINTERS = SectionType 0x05
-- ^ section with only pointers to literals

pattern S_NON_LAZY_SYMBOL_POINTERS :: SectionType
pattern S_NON_LAZY_SYMBOL_POINTERS = SectionType 0x06
-- ^ section with only non-lazy symbol pointers

pattern S_LAZY_SYMBOL_POINTERS :: SectionType
pattern S_LAZY_SYMBOL_POINTERS = SectionType 0x07
-- ^ section with only lazy symbol pointers

pattern S_SYMBOL_STUBS :: SectionType
pattern S_SYMBOL_STUBS = SectionType 0x08
-- ^ section with only symbol stubs, bte size of stub in the reserved2 field

pattern S_MOD_INIT_FUNC_POINTERS :: SectionType
pattern S_MOD_INIT_FUNC_POINTERS = SectionType 0x09
-- ^ section with only function pointers for initialization

pattern S_MOD_TERM_FUNC_POINTERS :: SectionType
pattern S_MOD_TERM_FUNC_POINTERS = SectionType 0x0a
-- ^ section with only function pointers for termination

pattern S_COALESCED :: SectionType
pattern S_COALESCED = SectionType 0x0b
-- ^ section contains symbols that are to be coalesced

pattern S_GB_ZEROFILL :: SectionType
pattern S_GB_ZEROFILL = SectionType 0x0c
-- ^ zero fill on demand section (that can be larger than 4 gigabytes)

pattern S_INTERPOSING :: SectionType
pattern S_INTERPOSING = SectionType 0x0d
-- ^ section with only pairs of function pointers for interposing

pattern S_16BYTE_LITERALS :: SectionType
pattern S_16BYTE_LITERALS = SectionType 0x0e
-- ^ section with only 16 byte literals

pattern S_DTRACE_DOF :: SectionType
pattern S_DTRACE_DOF = SectionType 0x0f
-- ^ section contains DTrace Object Format

pattern S_LAZY_DYLIB_SYMBOL_POINTERS :: SectionType
pattern S_LAZY_DYLIB_SYMBOL_POINTERS = SectionType 0x10
-- ^ section with only lazy symbol pointers to lazy loaded dylibs

-- | Return the type of the section
secType :: MachoSection w -> SectionType
secType = secAttrType . secFlags

-- | Parse the relocations for the given section in the mach-o file.
getSectionRelocs :: MachoFile -> MachoSection w -> Maybe [Relocation]
getSectionRelocs mfile s = getRelocations mfile (secReloff s) (secNReloc s)
