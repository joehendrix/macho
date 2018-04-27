{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
module Data.Macho.Pure.Symbols
  ( -- * Symbols
    MachoSymbol(..)
  , getSymTabEntries
    -- * Symbol type information
  , SymbolType(..)
  , pattern N_STAB
  , pattern N_PEXT
  , symbolTypeBits
  , pattern N_EXT
  , pattern N_GSYM
  , pattern N_FNAME
  , pattern N_FUN
  , pattern N_STSYM
  , pattern N_LCSYM
  , pattern N_BNSYM
  , pattern N_OPT
  , pattern N_RSYM
  , pattern N_SLINE
  , pattern N_ENSYM
  , pattern N_SSYM
  , pattern N_SO
  , pattern N_OSO
  , pattern N_LSYM
  , pattern N_BINCL
  , pattern N_SOL
  , pattern N_PARAMS
  , pattern N_VERSION
  , pattern N_OLEVEL
  , pattern N_PSYM
  , pattern N_EINCL
  , pattern N_ENTRY
  , pattern N_LBRAC
  , pattern N_EXCL
  , pattern N_RBRAC
  , pattern N_BCOMM
  , pattern N_ECOMM
  , pattern N_ECOML
  , pattern N_LENG
  , pattern N_PC
  , N_TYPE(..)
  , pattern N_UNDF
  , pattern N_ABS
  , pattern N_SECT
  , pattern N_PBUD
  , pattern N_INDR
    -- * REFERENCE_FLAG
  , REFERENCE_FLAG(..)
  , referenceType
  , referenceLibraryOrdinal
    -- ** Reference Types
  , REFERENCE_TYPE
  , pattern REFERENCE_FLAG_UNDEFINED_NON_LAZY
  , pattern REFERENCE_FLAG_UNDEFINED_LAZY
  , pattern REFERENCE_FLAG_DEFINED
  , pattern REFERENCE_FLAG_PRIVATE_DEFINED
  , pattern REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY
  , pattern REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY
    -- ** Other attributes
  , pattern REFERENCED_DYNAMICALLY
  , pattern N_WEAK_REF
  , pattern N_WEAK_DEF
  ) where

import           Data.Bits
import qualified Data.ByteString as B
import           Data.Word
import           Numeric (showHex)

import qualified Data.Vector as V
import           Data.Macho.Pure.Header (MH_MAGIC, magicWordSize)
import           Data.Macho.Pure.Commands (SymTabCommand(..))
import           Data.Macho.Pure.Decoder

------------------------------------------------------------------------
-- N_TYPE

-- | The 3-bits used for the type bits (mask = 0x0e).
newtype N_TYPE = N_TYPE Word8
  deriving (Eq, Show)

pattern N_UNDF :: N_TYPE
pattern N_UNDF = N_TYPE 0x0
-- ^ undefined symbol, n_sect is 0

pattern N_ABS :: N_TYPE
pattern N_ABS = N_TYPE 0x2
-- ^ absolute symbol, does not need relocation, n_sect is 0

pattern N_SECT :: N_TYPE
pattern N_SECT = N_TYPE 0xe
-- ^ symbol is defined in section n_sect

pattern N_PBUD :: N_TYPE
pattern N_PBUD = N_TYPE 0xc
-- ^ symbol is undefined and the image is using a prebound value for
-- the symbol, n_sect is 0

pattern N_INDR :: N_TYPE
pattern N_INDR = N_TYPE 0xa
-- ^ symbol is defined to be the same as another symbol. n_value is a
-- string table offset indicating the name of that symbol


------------------------------------------------------------------------
-- SymbolType

-- | The 8-bit @n_type@ field in a symbol table entry
newtype SymbolType = SymbolType Word8
  deriving (Eq, Bits, Num)

instance Show SymbolType where
  show (SymbolType w) = "0x" ++ showHex w ""

-- | If any of the bits in N_STAB are set, the symbol type is a
-- symbolic debugging entry.
--
-- This can be checked with @sym .&. N_STAB /= 0@.
pattern N_STAB :: SymbolType
pattern N_STAB = SymbolType 0xe0

-- | Private external symbol bit
pattern N_PEXT :: SymbolType
pattern N_PEXT = SymbolType 0x10

-- | Return the N_TYPE field.
symbolTypeBits :: SymbolType -> N_TYPE
symbolTypeBits (SymbolType x) = N_TYPE (x .&. 0x0e)

-- | External symbol bit, set for external symbols.
pattern N_EXT :: SymbolType
pattern N_EXT = SymbolType 0x01

pattern N_GSYM :: SymbolType
pattern N_GSYM = SymbolType 0x20
-- ^ stab global symbol: name,,0,type,0
pattern N_FNAME :: SymbolType
pattern N_FNAME = SymbolType 0x22
-- ^ stab procedure name (f77 kludge): name,,0,0,0
pattern N_FUN :: SymbolType
pattern N_FUN = SymbolType 0x24
-- ^ stab procedure: name,,n_sect,linenumber,address
pattern N_STSYM :: SymbolType
pattern N_STSYM = SymbolType 0x26
-- ^ stab static symbol: name,,n_sect,type,address
pattern N_LCSYM :: SymbolType
pattern N_LCSYM = SymbolType 0x28
-- ^ stab .lcomm symbol: name,,n_sect,type,address
pattern N_BNSYM :: SymbolType
pattern N_BNSYM = SymbolType 0x2e
-- ^ stab begin nsect sym: 0,,n_sect,0,address
pattern N_OPT :: SymbolType
pattern N_OPT = SymbolType 0x3c
-- ^ stab emitted with gcc2_compiled and in gcc source
pattern N_RSYM :: SymbolType
pattern N_RSYM = SymbolType 0x40
-- ^ stab register sym: name,,0,type,register
pattern N_SLINE :: SymbolType
pattern N_SLINE = SymbolType 0x44
-- ^ stab src line: 0,,n_sect,linenumber,address
pattern N_ENSYM :: SymbolType
pattern N_ENSYM = SymbolType 0x4e
-- ^ stab end nsect sym: 0,,n_sect,0,address
pattern N_SSYM :: SymbolType
pattern N_SSYM = SymbolType 0x60
-- ^ stab structure elt: name,,0,type,struct_offset
pattern N_SO :: SymbolType
pattern N_SO = SymbolType 0x64
-- ^ stab source file name: name,,n_sect,0,address
pattern N_OSO :: SymbolType
pattern N_OSO = SymbolType 0x66
-- ^ stab object file name: name,,0,0,st_mtime
pattern N_LSYM :: SymbolType
pattern N_LSYM = SymbolType 0x80
-- ^ stab local sym: name,,0,type,offset
pattern N_BINCL :: SymbolType
pattern N_BINCL = SymbolType 0x82
-- ^ stab include file beginning: name,,0,0,sum
pattern N_SOL :: SymbolType
pattern N_SOL = SymbolType 0x84
-- ^ stab #included file name: name,,n_sect,0,address
pattern N_PARAMS :: SymbolType
pattern N_PARAMS = SymbolType 0x86
-- ^ stab compiler parameters: name,,0,0,0
pattern N_VERSION :: SymbolType
pattern N_VERSION = SymbolType 0x88
-- ^ stab compiler version: name,,0,0,0
pattern N_OLEVEL :: SymbolType
pattern N_OLEVEL = SymbolType 0x8a
-- ^ stab compiler -O level: name,,0,0,0
pattern N_PSYM :: SymbolType
pattern N_PSYM = SymbolType 0xa0
-- ^ stab parameter: name,,0,type,offset
pattern N_EINCL :: SymbolType
pattern N_EINCL = SymbolType 0xa2
-- ^ stab include file end: name,,0,0,0
pattern N_ENTRY :: SymbolType
pattern N_ENTRY = SymbolType 0xa4
-- ^ stab alternate entry: name,,n_sect,linenumber,address
pattern N_LBRAC :: SymbolType
pattern N_LBRAC = SymbolType 0xc0
-- ^ stab left bracket: 0,,0,nesting level,address
pattern N_EXCL :: SymbolType
pattern N_EXCL = SymbolType 0xc2
-- ^ stab deleted include file: name,,0,0,sum
pattern N_RBRAC :: SymbolType
pattern N_RBRAC = SymbolType 0xe0
-- ^ stab right bracket: 0,,0,nesting level,address
pattern N_BCOMM :: SymbolType
pattern N_BCOMM = SymbolType 0xe2
-- ^ stab begin common: name,,0,0,0
pattern N_ECOMM :: SymbolType
pattern N_ECOMM = SymbolType 0xe4
-- ^ stab end common: name,,n_sect,0,0
pattern N_ECOML :: SymbolType
pattern N_ECOML = SymbolType 0xe8
-- ^ stab end common (local name): 0,,n_sect,0,address
pattern N_LENG :: SymbolType
pattern N_LENG = SymbolType 0xfe
-- ^ stab second stab entry with length information
pattern N_PC :: SymbolType
pattern N_PC = SymbolType 0x30
-- ^ stab global pascal symbol: name,,0,subtype,line

------------------------------------------------------------------------
-- REFERENCE_TYPE

-- | A 4-bit refeence flag definition
newtype REFERENCE_TYPE = REFERENCE_TYPE Word8

pattern REFERENCE_FLAG_UNDEFINED_NON_LAZY :: REFERENCE_TYPE
pattern REFERENCE_FLAG_UNDEFINED_NON_LAZY = REFERENCE_TYPE 0
-- ^ reference to an external non-lazy symbol

pattern REFERENCE_FLAG_UNDEFINED_LAZY :: REFERENCE_TYPE
pattern REFERENCE_FLAG_UNDEFINED_LAZY = REFERENCE_TYPE 1
-- ^ reference to an external lazy symbol

pattern REFERENCE_FLAG_DEFINED :: REFERENCE_TYPE
pattern REFERENCE_FLAG_DEFINED = REFERENCE_TYPE 2
-- ^ symbol is defined in this module

pattern REFERENCE_FLAG_PRIVATE_DEFINED :: REFERENCE_TYPE
pattern REFERENCE_FLAG_PRIVATE_DEFINED =  REFERENCE_TYPE 3
-- ^ symbol is defined in this module and visible only to modules within this shared library

pattern REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY :: REFERENCE_TYPE
pattern REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY =  REFERENCE_TYPE 4
-- ^ reference to an external non-lazy symbol and visible only to modules within this shared library

pattern REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY :: REFERENCE_TYPE
pattern REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY =  REFERENCE_TYPE 5
-- ^ reference to an external lazy symbol and visible only to modules within this shared library

------------------------------------------------------------------------
-- REFERENCE_FLAG

newtype REFERENCE_FLAG = REFERENCE_FLAG Word16
  deriving (Eq, Bits)

instance Show REFERENCE_FLAG where
  showsPrec p (REFERENCE_FLAG w) = showParen (p >= 10) $ showString "REFERENCE_FLAG " . showHex w

-- | The low 4-order bits used to define the reference type.
referenceType :: REFERENCE_FLAG -> REFERENCE_TYPE
referenceType (REFERENCE_FLAG w) = REFERENCE_TYPE (fromIntegral (w .&. 0xf))

-- | The number of the library that defines this symbol
--
-- This is only meaningful in @MH_TWOLEVEL@ files.
referenceLibraryOrdinal :: REFERENCE_FLAG -> Word8
referenceLibraryOrdinal (REFERENCE_FLAG w) = fromIntegral (w `shiftR` 8)

pattern REFERENCED_DYNAMICALLY :: REFERENCE_FLAG
pattern REFERENCED_DYNAMICALLY = REFERENCE_FLAG 0x10
-- ^ set for all symbols referenced by dynamic loader APIs

pattern N_WEAK_REF :: REFERENCE_FLAG
pattern N_WEAK_REF = REFERENCE_FLAG 0x40
-- ^ indicates the symbol is a weak reference, set to 0 if definition cannot be found

pattern N_WEAK_DEF :: REFERENCE_FLAG
pattern N_WEAK_DEF = REFERENCE_FLAG 0x80
-- ^ indicates the symbol is a weak definition, will be overridden by
-- a strong definition at link-time


------------------------------------------------------------------------
-- MachoSymbol

data MachoSymbol = MachoSymbol
    { sym_name  :: !B.ByteString -- ^ symbol name
    , sym_type  :: !SymbolType -- ^ symbol type
    , sym_sect  :: Word8                          -- ^ section index where the symbol can be found
    , sym_flags :: Either Word16 REFERENCE_FLAG -- ^ for stab entries, Left Word16 is the uninterpreted flags field, otherwise Right REFERENCE_FLAG describes the symbol flags.
    , sym_value :: Word64                         -- ^ symbol value, 32-bit symbol values are promoted to 64-bit for simpliciy
    } deriving (Show, Eq)

-- | Returns the symbol table entry size
symtabEntrySize :: MH_MAGIC -> Word32
symtabEntrySize magic = 8 + magicWordSize magic

-- | Parse a null-terminated string from an offset in the symbol
getSymbolName :: B.ByteString -> Decoder B.ByteString
getSymbolName strsect = do
  offset <- getWord32
  pure $!
    if offset == 0 then
      B.empty
     else
      B.takeWhile (/= 0) (B.drop (fromIntegral offset) strsect)

getNList :: B.ByteString -> Decoder MachoSymbol
getNList strsect = do
  n_name  <- getSymbolName strsect
  typeCode  <- SymbolType <$> getWord8
  n_sect  <- getWord8
  n_desc  <- getWord16
  let ref_flags = if typeCode .&. N_STAB /= 0 then
                      Left n_desc
                  else
                      Right $ REFERENCE_FLAG n_desc
  n_value <- getWord
  return $ MachoSymbol { sym_name = n_name
                       , sym_type = typeCode
                       , sym_sect = n_sect
                       , sym_flags = ref_flags
                       , sym_value = n_value
                       }


-- | This attempts to parse the symbol table entries from the command info
getSymTabEntries :: MachoFile -> SymTabCommand -> Maybe (V.Vector MachoSymbol)
getSymTabEntries mfile cmd = do
  strsect <- subbuffer (machoContents mfile) (symTabStrOffset cmd) (symTabStrSize cmd)
  V.fromList <$>
    getTable mfile (symTabOffset cmd) (symTabSymCount cmd)
             (symtabEntrySize (machoMagic mfile)) (getNList strsect)
