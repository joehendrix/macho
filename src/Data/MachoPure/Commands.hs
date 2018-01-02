{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{- LANGUAGE MultiParamTypeClasses -}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.MachoPure.Commands
  ( -- * Commands
    LC_COMMAND(..)
  , ppLoadCommand
  , FileOffset(..)
  , UUID
  , LCStr(..)
  , SymTabCommand(..)
  , SymSegCommand(..)
  , DylibCommand(..)
  , FVMLibCommand(..)
  , FVMFileCommand(..)
  , PreboundDylibCommand(..)
  , preboundIsBound
  , ThreadCommand(..)
  , EncryptionInfoCommand(..)
  , getEncryptionInfoCommand
  , DyldInfoCommand(..)
  , VersionMinCommand(..)
  , EntryPointCommand(..)
    -- * Segments
  , MachoSegment(..)
  , Addr(..)
  , SegmentName
  , getSegmentName
    -- ** Segment flags
  , SG_FLAGS(..)
  , pattern SG_HIGHVM
  , pattern SG_NORELOC
    -- ** Virtual memory protections
  , VM_PROT(..)
  , pattern VM_PROT_READ
  , pattern VM_PROT_WRITE
  , pattern VM_PROT_EXECUTE
    -- * Sections
  , MachoSection(..)
  , secType
  , Align(..)
  , SectionName
  , getSectionName
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
    -- * Dynamic symbol table
  , DysymtabCommand(..)
  , DylibModule(..)
    -- * LINKEDIT information
  , LinkeditDataCommand(..)
    -- * Linker options
  , LinkerOptionCommand(..)
    -- * Build information
  , BuildVersionCommand(..)
    -- ** Platform
  , Platform
  , pattern PLATFORM_MACOS
  , pattern PLATFORM_IOS
  , pattern PLATFORM_TVOS
  , pattern PLATFORM_WATCHOS
  , pattern PLATFORM_BRIDGEOS
    -- ** Tool version
  , BuildToolVersion(..)
  , Tool
  , pattern TOOL_CLANG
  , pattern TOOL_SWIFT
  , pattern TOOL_LD
    -- * Support
  , CommandType(..)
  ) where

import           Control.Monad
import           Data.Binary.Get hiding (Decoder)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.UTF8 as UTF8
import           Data.Monoid
import           Data.String
import           Data.Word
import           Numeric (showHex)

import Data.MachoPure.Decoder

showPadHex :: (Integral a, Show a) => Int -> a -> String
showPadHex c a = "0x" ++ replicate (c - length s) '0' ++ s
  where s = showHex a ""

------------------------------------------------------------------------
-- Addr

newtype Addr = Addr Word64
  deriving (Eq)

instance Show Addr where
  show (Addr a) = showPadHex 16 a

------------------------------------------------------------------------
-- CommandType

-- | A class for values that can be decoded from a command.
class CommandType a where
  -- Return the value after reading it.
  getValue :: B.ByteString ->  Decoder a

instance CommandType Word32 where
  getValue _ = getWord32

instance CommandType Word64 where
  getValue _ = getWord64

------------------------------------------------------------------------
-- MachoRecord

-- | Type-directed records
class MachoRecord a b where
  -- | Read a record
  getRecord :: a -> B.ByteString -> Decoder b

instance MachoRecord a a where
  getRecord x _ = pure $! x

instance (CommandType a, MachoRecord b c) => MachoRecord (a -> b) c where
  getRecord f lc = getValue lc >>= \v -> getRecord (f v) lc

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
  show (S_ATTR x) = showPadHex 8 x

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
-- MachoSection

-- | An alignment field
newtype Align = Align Word32
  deriving (Eq)

instance Show Align where
  show (Align w) = "2^" ++ show w ++ "(" ++ show (2^w :: Integer) ++ ")"

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

-- | Return the type of the section
secType :: MachoSection w -> SectionType
secType = secAttrType . secFlags

ppAttr :: String -> String -> String
ppAttr nm v = nm ++ " " ++ v ++ "\n"

ppSection :: Show  w => MachoSection w -> String
ppSection s
  = "Section\n"
  ++ ppAttr "  sectname" (show (secSectname s))
  ++ ppAttr "   segname" (show (secSegname s))
  ++ ppAttr "      addr" (show (secAddr s))
  ++ ppAttr "      size" (show (secSize s))
  ++ ppAttr "    offset" (show (secAlign s))
  ++ ppAttr "    reloff" (show (secReloff s))
  ++ ppAttr "    nreloc" (show (secNReloc s))
  ++ ppAttr "     flags" (show (secFlags s))
  ++ ppAttr " reserved1" (show (secReserved1 s))
  ++ ppAttr " reserved2" (show (secReserved2 s))

instance CommandType w => CommandType (MachoSection w) where
  getValue lc = do
    sectname  <- lift $ getSectionName
    segname   <- lift $ getSegmentName
    addr      <- getValue lc
    size      <- getValue lc
    offset    <- getWord32
    align     <- Align <$> getWord32
    reloff    <- FileOffset <$> getWord32
    nreloc    <- getWord32
    flags     <- S_ATTR <$> getWord32
    reserved1 <- getWord32
    reserved2 <- getValue lc
    return MachoSection { secSectname    = sectname
                        , secSegname     = segname
                        , secAddr        = addr
                        , secSize        = size
                        , secOffset      = offset
                        , secAlign       = align
                        , secReloff      = reloff
                        , secNReloc      = nreloc
                        , secFlags       = flags
                        , secReserved1   = reserved1
                        , secReserved2   = reserved2
                        }

------------------------------------------------------------------------
-- VM_PROT

-- | Protection flags for memory
newtype VM_PROT = VM_PROT { vmProtValue :: Word32 }
  deriving (Eq, Bits)

instance Show VM_PROT where
  show (VM_PROT v) = showPadHex 8 v

pattern VM_PROT_READ :: VM_PROT
pattern VM_PROT_READ = VM_PROT 0x1
-- ^ read permission

pattern VM_PROT_WRITE :: VM_PROT
pattern VM_PROT_WRITE = VM_PROT 0x2
-- ^ write permission

pattern VM_PROT_EXECUTE :: VM_PROT
pattern VM_PROT_EXECUTE = VM_PROT 0x4
-- ^ execute permission

------------------------------------------------------------------------
-- Segment flags

-- | Segment flags
newtype SG_FLAGS = SG_FLAGS Word32
  deriving (Eq, Bits)

pattern SG_HIGHVM :: SG_FLAGS
pattern SG_HIGHVM = SG_FLAGS 1
-- ^ The file contents for this segment is for the high part of the VM
-- space, the low part is zero filled (for stacks in core files).

pattern SG_NORELOC :: SG_FLAGS
pattern SG_NORELOC = SG_FLAGS 4
-- ^ This segment has nothing that was relocated in it and nothing
-- relocated to it, that is it may be safely replaced without
-- relocation.

instance Show SG_FLAGS where
  show (SG_FLAGS x) = "0x" ++ showHex x ""

------------------------------------------------------------------------
-- MachoSegment

-- | Information about a segment
data MachoSegment w = MachoSegment
    { seg_segname  :: !SegmentName    -- ^ segment name
    , seg_vmaddr   :: !w              -- ^ virtual address where the segment is loaded
    , seg_vmsize   :: !w              -- ^ size of segment at runtime
    , seg_fileoff  :: !w              -- ^ file offset of the segment
    , seg_filesize :: !w              -- ^ size of segment in file
    , seg_maxprot  :: !VM_PROT        -- ^ maximum virtual memory protection
    , seg_initprot :: !VM_PROT        -- ^ initial virtual memory protection
    , seg_flags    :: !SG_FLAGS       -- ^ segment flags
    , seg_sections :: ![MachoSection w] -- ^ sections owned by this segment
    } deriving (Show, Eq)

instance CommandType w => CommandType (MachoSegment w) where
  getValue lc = do
    segname  <- lift $ getSegmentName
    vmaddr   <- getValue lc
    vmsize   <- getValue lc
    fileoff  <- getValue lc
    filesize <- getValue lc
    maxprot  <- VM_PROT <$> getWord32
    initprot <- VM_PROT <$> getWord32
    nsects   <- getWord32
    flags    <- SG_FLAGS <$> getWord32
    sects    <- replicateM (fromIntegral nsects) (getValue lc)
    return $ MachoSegment { seg_segname  = segname
                          , seg_vmaddr   = vmaddr
                          , seg_vmsize   = vmsize
                          , seg_fileoff  = fileoff
                          , seg_filesize = filesize
                          , seg_maxprot  = maxprot
                          , seg_initprot = initprot
                          , seg_flags    = flags
                          , seg_sections = sects
                          }


------------------------------------------------------------------------
-- DylibModule

data DylibModule = DylibModule
    { dylib_module_name_offset    :: Word32           -- ^ module name string table offset
    , dylib_ext_def_sym           :: (Word32, Word32) -- ^ (initial, count) pair of symbol table indices for externally defined symbols
    , dylib_ref_sym               :: (Word32, Word32) -- ^ (initial, count) pair of symbol table indices for referenced symbols
    , dylib_local_sym             :: (Word32, Word32) -- ^ (initial, count) pair of symbol table indices for local symbols
    , dylib_ext_rel               :: (Word32, Word32) -- ^ (initial, count) pair of symbol table indices for externally referenced symbols
    , dylib_init                  :: (Word32, Word32) -- ^ (initial, count) pair of symbol table indices for the index of the module init section and the number of init pointers
    , dylib_term                  :: (Word32, Word32) -- ^ (initial, count) pair of symbol table indices for the index of the module term section and the number of term pointers
    , dylib_objc_module_info_addr :: Word64           -- ^ statically linked address of the start of the data for this module in the __module_info section in the __OBJC segment
    , dylib_objc_module_info_size :: Word32           -- ^ number of bytes of data for this module that are used in the __module_info section in the __OBJC segment
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- FileOffset

newtype FileOffset = FileOffset { fileOffsetValue :: Word32 }
  deriving (Eq, Show)

instance CommandType FileOffset where
  getValue _ = FileOffset <$> getWord32

------------------------------------------------------------------------
-- SymTabCommand

-- | Information from a symbol table command
data SymTabCommand = SymTabCommand { symTabOffset :: !FileOffset
                                   , symTabSymCount :: !Word32
                                   , symTabStrOffset :: !FileOffset
                                   , symTabStrSize :: !Word32
                                   }
  deriving (Eq, Show)

instance CommandType SymTabCommand where
  getValue = getRecord SymTabCommand

------------------------------------------------------------------------
-- SymSegCommand

-- | The symseg_command contains the offset and size of the GNU style
--symbol table information as described in the header file <symseg.h>.
data SymSegCommand = SymSegCommand { symSegOffset :: !FileOffset
                                   , symSegSize   :: !Word32
                                   }
  deriving (Eq, Show)

instance CommandType SymSegCommand where
  getValue = getRecord SymSegCommand

------------------------------------------------------------------------
-- LCStr

-- | Represents a lcstring excluding the terminating string
newtype LCStr = LCStr B.ByteString
  deriving (Eq)

instance Show LCStr where
  show (LCStr x) = C.unpack x

-- | Read a load command string given the bytes for the command.
instance CommandType LCStr where
  getValue lc = LCStr . (`nullStringAt` lc) <$> getWord32

------------------------------------------------------------------------
-- ThreadCommand

-- | Machine-specific datastructure sfor thread state primitives (used
-- by LC_THREAD and LC_UNIXTHREAD).
data ThreadCommand
  = ThreadCommand
  { threadFlavor :: !Word32
    -- ^ Architecture-specific identifier for a thread state flavor
  , threadData :: !B.ByteString
    -- ^ Flavor-specific data value (size should be a multiple of 4)
  }
  deriving (Eq, Show)

instance CommandType ThreadCommand where
  getValue _ = do
    flavor <- getWord32
    count <- getWord32
    when (count >= 2^(30::Int)) $ do
      fail $ "Thread command count is to large " ++ show count
    threadState <- lift $ getByteString (4 * fromIntegral count)
    pure ThreadCommand { threadFlavor = flavor
                       , threadData = threadState
                       }

------------------------------------------------------------------------
-- FVMLibCommand

data FVMLibCommand = FVMLibCommand { fvmlibNameOffset   :: !LCStr
                                   , fvmlibMinorVersion :: !Word32
                                   , fvmlibHeaderAddr   :: !Word32
                                   }
  deriving (Eq, Show)

instance CommandType FVMLibCommand where
  getValue = getRecord FVMLibCommand

------------------------------------------------------------------------
-- FVMFileCommand

-- | A reference to a file to be loaded at a specific virtual address.
--
-- This command is reserved for internal use and ignored by kernel.
data FVMFileCommand
  = FVMFileCommand
  { fvmfileName :: !LCStr
  , fvmfileHeaderAddr :: !Word32
  }
 deriving (Eq, Show)

instance CommandType FVMFileCommand where
  getValue = getRecord FVMFileCommand

------------------------------------------------------------------------
-- DysymtabCommand

-- | Dynamic symbol table command
data DysymtabCommand = DysymtabCommand
    { dysymtabILocalSym  :: !Word32 -- ^ Index to local symbols
    , dysymtabNLocalSym  :: !Word32 -- ^ Number of local symbols
    , dysymtabIExtdefSym :: !Word32 -- ^ Index to externally defined symbols
    , dysymtabNExtdefSym :: !Word32 -- ^ Number of externally defined symbols
    , dysymtabIUndefSym  :: !Word32 -- ^ Index to undefined symbols
    , dysymtabNUndefSym  :: !Word32 -- ^ Number of undefined symbols

    , dysymtabTocOff         :: !FileOffset        -- ^ Offset for symbol table of contents
    , dysymtabTocCount       :: !Word32            -- ^ Number of symbols in contents.
    , dysymtabModtabOff      :: !FileOffset        -- ^ Offset for modules
    , dysymtabModtabCount    :: !Word32            -- ^ Number of modules.
    , dysymtabExtrefSymOff   :: !FileOffset        -- ^ Offset of external symbol reference indices
    , dysymtabExtrefSymCount :: !Word32            -- ^ Number of external reference symbol indices
    , dysymtabIndirectSymOff   :: !FileOffset   -- ^ Offset of indirect symbol indices
    , dysymtabIndirectSymCount :: !Word32       -- ^ Number of indirect symbol indices
    , dysymtabExtRelOff     :: !FileOffset   -- ^ External relocation table offset
    , dysymtabExtRelCount   :: !Word32       -- ^ External relocation count
    , dysymtabLocalRelOff   :: !FileOffset   -- ^ Local relocation table offset
    , dysymtabLocalRelCount :: !Word32       -- ^ Local relocation count
    } deriving (Show, Eq)

instance CommandType DysymtabCommand where
  getValue = getRecord DysymtabCommand

------------------------------------------------------------------------
-- DylibCommand

data DylibCommand = DylibCommand { symlibNameOffset :: !LCStr
                                 , symlibTimestamp :: !Word32
                                 , symlibCurrentVersion :: !Word32
                                 , symlibCompatibilityVersion :: !Word32
                                 }
  deriving (Eq, Show)

instance CommandType DylibCommand where
  getValue = getRecord DylibCommand

------------------------------------------------------------------------
-- PreboundDylibCommand

-- | A dynamic library that uses prebound.
data PreboundDylibCommand
   = PreboundDylibCommand
   { preboundName :: !LCStr
     -- ^ Name of path library
   , preboundCount :: !Word32
     -- ^ Number of modules in library
   , preboundLinked :: !B.ByteString
     -- ^ Linked library module.
   }
 deriving (Eq, Show)

-- | Return true if the module at the given index.
preboundIsBound :: PreboundDylibCommand -> Word32 -> Maybe Bool
preboundIsBound c i
  | byteOff < B.length b = Just $ (B.index b byteOff) `testBit` bitOff
  | otherwise = Nothing
  where byteOff = fromIntegral (i `shiftR` 3)
        bitOff  = fromIntegral (i .&. 0x7)
        b = preboundLinked c

instance CommandType PreboundDylibCommand where
  getValue lc = do
    name           <- getValue lc
    nmodules       <- getWord32
    modules_offset <- getWord32
    let cnt = fromIntegral (nmodules `shiftR` 3) + (if nmodules .&. 0x7 == 0 then 0 else 1)
    let mods = B.take cnt $ B.drop (fromIntegral modules_offset) lc
    return $ PreboundDylibCommand
      { preboundName = name
      , preboundCount = nmodules
      , preboundLinked = mods
      }

------------------------------------------------------------------------
-- RoutinesCommand

-- | A 128-bit bytestring with a UUID for the image.
data RoutinesCommand w
  = RoutinesCommand
  { routinesInitAddress :: !w
  , routinesInitModule  :: !w
  }
  deriving (Eq, Show)

instance CommandType w => CommandType (RoutinesCommand w) where
  getValue lc = do
    init_address <- getValue lc
    init_module  <- getValue lc
    replicateM_ 6 (getValue lc :: Decoder w)
    pure $ RoutinesCommand { routinesInitAddress = init_address
                           , routinesInitModule  = init_module
                           }

------------------------------------------------------------------------
-- UUID

-- | A 128-bit bytestring with a UUID for the image.
newtype UUID = UUID B.ByteString
  deriving (Eq)

instance Show UUID where
  -- UUIDs have the format BDFAAB38-B160-30D2-8549-B94A-FD2F-1B1F
  showsPrec _ (UUID b) =
    digits 0 3 . ('-':) . digits 4 5 . ('-':) . digits 6 7 . ('-':) . digits 8 9 . ('-' :) . digits 10 15
    where digits :: Int -> Int -> ShowS
          digits l h
            | l > h = id
            | otherwise = showByte (b `B.index` l) . digits (l+1) h
          -- Show a byte as 2 digit hex
          showByte :: Word8 -> ShowS
          showByte w | w < 0x10  = ('0' :) . hex w
                     | otherwise = hex (w `shiftR` 4) . hex (w .&. 0xf)
          -- Print a hex digit with uppercase.
          hex :: Word8 -> ShowS
          hex w s
            | w < 10    = toEnum (fromEnum '0' + fromIntegral w) : s
            | otherwise = toEnum (fromEnum 'A' + fromIntegral w) : s

instance CommandType UUID where
  getValue _ = lift $ UUID <$> getByteString 16

------------------------------------------------------------------------
-- EncryptionInfoCommand

data EncryptionInfoCommand
  = EncryptionInfoCommand
  { cryptOff :: !Word32
  , cryptSize :: !Word32
  , cryptId   :: !Word32
  }
  deriving (Eq, Show)

getEncryptionInfoCommand :: Int -> Decoder EncryptionInfoCommand
getEncryptionInfoCommand paddingCount = do
  off  <- getWord32
  size <- getWord32
  tid  <- getWord32
  lift $ skip paddingCount
  pure EncryptionInfoCommand
    { cryptOff = off
    , cryptSize = size
    , cryptId   = tid
    }

------------------------------------------------------------------------
-- DyldInfoCommand

data DyldInfoCommand
  = DyldInfoCommand
  { rebaseOff    :: !Word32
  , rebaseSize   :: !Word32
  , bindOff      :: !Word32
  , bindSize     :: !Word32
  , weakBindOff  :: !Word32
  , weakBindSize :: !Word32
  , lazyBindOff  :: !Word32
  , lazyBindSize :: !Word32
  , exportOff    :: !Word32
  , exportSize   :: !Word32
  }
  deriving (Eq, Show)

instance CommandType DyldInfoCommand where
  getValue = getRecord DyldInfoCommand

------------------------------------------------------------------------
-- Version

newtype Version = Version Word32
  deriving (Eq,Show)

instance CommandType Version where
  getValue _ = Version <$> getWord32


------------------------------------------------------------------------
-- VersionMinCommand

data VersionMinCommand
  = VersionMinCommand
  { versionVersion :: !Version
  , versionSDK :: !Version
  } deriving (Eq, Show)

instance CommandType VersionMinCommand where
  getValue = getRecord VersionMinCommand


------------------------------------------------------------------------
-- Platform

newtype Platform = Platform Word32
  deriving (Eq, Show)

pattern PLATFORM_MACOS :: Platform
pattern PLATFORM_MACOS = Platform 1

pattern PLATFORM_IOS :: Platform
pattern PLATFORM_IOS = Platform 2

pattern PLATFORM_TVOS :: Platform
pattern PLATFORM_TVOS = Platform 3

pattern PLATFORM_WATCHOS :: Platform
pattern PLATFORM_WATCHOS = Platform 4

pattern PLATFORM_BRIDGEOS :: Platform
pattern PLATFORM_BRIDGEOS = Platform 5

instance CommandType Platform where
  getValue _ = Platform <$> getWord32

------------------------------------------------------------------------
-- Tool

-- | Identifier for tool
newtype Tool = Tool Word32
  deriving (Eq, Show)

pattern TOOL_CLANG :: Tool
pattern TOOL_CLANG = Tool 1

pattern TOOL_SWIFT :: Tool
pattern TOOL_SWIFT = Tool 2

pattern TOOL_LD :: Tool
pattern TOOL_LD = Tool 3

instance CommandType Tool where
  getValue _ = Tool <$> getWord32

------------------------------------------------------------------------
-- BuildToolVersion

data BuildToolVersion
  = BuildToolVersion
  { buildToolValue :: !Tool
  , buildToolVersion :: !Version
  }
  deriving (Eq, Show)

instance CommandType BuildToolVersion where
  getValue = getRecord BuildToolVersion

------------------------------------------------------------------------
-- BuildVersionCommand

data BuildVersionCommand
  = BuildVersionCommand
  { buildPlatform :: !Platform
  , buildMinOS :: !Version
  , buildSDK   :: !Version
  , buildTools :: ![BuildToolVersion]
  } deriving (Eq, Show)

instance CommandType BuildVersionCommand where
  getValue lc = do
    p <- getValue lc
    os <- getValue lc
    sdk <- getValue lc
    ntools <- getWord32
    tools <- replicateM (fromIntegral ntools) $ getValue lc
    pure BuildVersionCommand
      { buildPlatform = p
      , buildMinOS = os
      , buildSDK = sdk
      , buildTools = tools
      }

------------------------------------------------------------------------
-- EntryPointCommand

data EntryPointCommand = EntryPointCommand
  { entryOff :: !Word64
    -- ^ Offset of main in __TEXT
  , stackSize :: !Word64
    -- ^ If non-zero, initial stack size.
  }
  deriving (Eq, Show)

instance CommandType EntryPointCommand where
  getValue = getRecord EntryPointCommand

------------------------------------------------------------------------
-- LinkeditDataCommand

data LinkeditDataCommand = LinkeditDataCommand
  { linkeditDataOff :: !Word32
    -- ^ Offset of data in linkedit segment.
  , linkeditDataSize :: !Word32
    -- ^ Size of data in linkedit segment.
  }
  deriving (Eq, Show)

instance CommandType LinkeditDataCommand where
  getValue = getRecord LinkeditDataCommand

------------------------------------------------------------------------
-- LinkerOptionCommand

newtype LinkerOptionCommand =
  LinkerOptionCommand
  { linkerOptions :: [UTF8.ByteString]
    -- ^ Linker option strings.
  }
  deriving (Eq, Show)

getUTF8String :: Get UTF8.ByteString
getUTF8String = L.toStrict <$> getLazyByteStringNul

instance CommandType LinkerOptionCommand where
  getValue _ = do
    cnt <- getWord32
    lift $ LinkerOptionCommand <$> replicateM (fromIntegral cnt) getUTF8String


------------------------------------------------------------------------
-- LC_COMMAND

data LC_COMMAND
    = LC_SEGMENT !(MachoSegment Word32)
      -- ^ segment of this file to be mapped
    | LC_SYMTAB !SymTabCommand
      -- ^ static link-edit symbol table and stab info
    | LC_SYMSEG !SymSegCommand
      -- ^ Obsolete GNU style symbol table information
    | LC_THREAD !ThreadCommand
      -- ^ thread state information (list of (flavor, [long]) pairs)
    | LC_UNIXTHREAD !ThreadCommand
      -- ^ unix thread state information (includes a stack) (list of (flavor, [long] pairs)
    | LC_LOADFVMLIB !FVMLibCommand
      -- ^ The identifier of a fixed virtual shared library that an object uses.
    | LC_IDFVMLIB !FVMLibCommand
      -- ^ The identifier for a fixed virtual shared library
    | LC_IDENT !B.ByteString
      -- ^ Obsolete command with a free format null terminated string table.
    | LC_FVMFILE !FVMFileCommand
      -- ^ Command used internally to load
    | LC_PREPAGE !B.ByteString
      -- ^ Command for internal use only.
    | LC_DYSYMTAB !DysymtabCommand
      -- ^ dynamic link-edit symbol table info
    | LC_LOAD_DYLIB !DylibCommand
      -- ^ load a dynamically linked shared library (name, timestamp, current version, compatibility version)
    | LC_ID_DYLIB !DylibCommand
      -- ^ dynamically linked shared lib ident (name, timestamp, current version, compatibility version)
    | LC_LOAD_DYLINKER !LCStr
      -- ^ load a dynamic linker (name of dynamic linker)
    | LC_ID_DYLINKER !LCStr
      -- ^ dynamic linker identification (name of dynamic linker)
    | LC_PREBOUND_DYLIB !PreboundDylibCommand
      -- ^ modules prebound for a dynamically linked shared library (name, list of module indices)
    | LC_ROUTINES !(RoutinesCommand Word32)
      -- ^ image routines (virtual address of initialization routine, module index where it resides)
    | LC_SUB_FRAMEWORK !LCStr
      -- ^ sub framework (name)
    | LC_SUB_UMBRELLA !LCStr
      -- ^ sub umbrella (name)
    | LC_SUB_CLIENT !LCStr
      -- ^ sub client (name)
    | LC_SUB_LIBRARY !LCStr
      -- ^ sub library (name)
    | LC_TWOLEVEL_HINTS !FileOffset !Word32
      -- ^ A two-level hints table contains an offset into a two-level hints table
      -- and the number of hints.
    | LC_PREBIND_CKSUM !Word32
      -- ^ prebind checksum (checksum)
    | LC_LOAD_WEAK_DYLIB !DylibCommand
      -- ^ load a dynamically linked shared library that is allowed to be missing (symbols are weak imported) (name, timestamp, current version, compatibility version)
    | LC_SEGMENT_64 !(MachoSegment Word64)
      -- ^ 64-bit segment of this file to mapped
    | LC_ROUTINES_64 !(RoutinesCommand Word64)
      -- ^ 64-bit image routines (virtual address of initialization routine, module index where it resides)
    | LC_UUID !UUID
      -- ^ the uuid for an image or its corresponding dsym file (8 element list of bytes)
    | LC_RPATH !LCStr
      -- ^ runpath additions (path)
    | LC_CODE_SIGNATURE !LinkeditDataCommand
      -- ^ local of code signature
    | LC_SEGMENT_SPLIT_INFO !LinkeditDataCommand
      -- ^ local of info to split segments
    | LC_REEXPORT_DYLIB !DylibCommand
      -- ^ A library that is re-exported by this library.
    | LC_LAZY_LOAD_DYLIB !DylibCommand
      -- ^ A dynamic library that is lazy loaded.
    | LC_ENCRYPTION_INFO !EncryptionInfoCommand
      -- ^ Encryption info
    | LC_DYLD_INFO      !DyldInfoCommand
      -- ^ Information needed by the dynamic linker to load a file.
    | LC_DYLD_INFO_ONLY !DyldInfoCommand
      -- ^ Information needed by the dynamic linker to load a file.
    | LC_LOAD_UPWARD_DYLIB !DylibCommand
      -- ^ Load upward dylib
    | LC_VERSION_MIN_MACOSX !VersionMinCommand
      -- ^ MacOSX min version
    | LC_VERSION_MIN_IPHONEOS !VersionMinCommand
      -- ^ iPhoneOS min version
    | LC_FUNCTION_STARTS !LinkeditDataCommand
    | LC_DYLD_ENVIRONMENT !LCStr
    | LC_MAIN !EntryPointCommand
    | LC_DATA_IN_CODE !LinkeditDataCommand
    | LC_SOURCE_VERSION !Version
    | LC_DYLIB_CODE_SIGN_DRS !LinkeditDataCommand
    | LC_ENCRYPTION_INFO_64 !EncryptionInfoCommand
      -- ^ Encryption info
    | LC_LINKER_OPTION !LinkerOptionCommand
    | LC_LINKER_OPTIMIZATION_HINT !LinkeditDataCommand
    | LC_VERSION_MIN_TVOS !VersionMinCommand
      -- ^ AppleTV min version
    | LC_VERSION_MIN_WATCHOS !VersionMinCommand
      -- ^ Watch min version
    | LC_NOTE !B.ByteString
      -- ^ Arbitrary note
    | LC_BUILD_VERSION !BuildVersionCommand
      -- ^ Watch min version

    | LC_INVALID !Word32 !B.ByteString !ByteOffset !String
      -- ^ Load command had a known type, but we could not interpret the
      -- contents.
      --
      -- The fields contain the command type code, the contents, the offset of the
      -- error and an error message.
    | LC_UNKNOWN !Word32 !B.ByteString
      -- ^ The load command had an unknown command type code.
      --
      -- The fields contain the command type code and the contents of the buffer.
    deriving (Show, Eq)

-- | Pretty print load commands in a style similiar to otool.
ppLoadCommand :: LC_COMMAND -> String
ppLoadCommand (LC_SEGMENT_64 s)
  =  ppAttr "      cmd" "LC_SEGMENT_64"
  ++ ppAttr "  segname" (show (seg_segname s))
  ++ ppAttr "   vmaddr" (show (seg_vmaddr s))
  ++ ppAttr "   vmsize" (show (seg_vmsize s))
  ++ ppAttr "  fileoff" (show (seg_fileoff s))
  ++ ppAttr " filesize" (show (seg_filesize s))
  ++ ppAttr "  maxprot" (show (seg_maxprot s))
  ++ ppAttr " initprot" (show (seg_initprot s))
  ++ ppAttr "   nsects" (show (length (seg_sections s)))
  ++ ppAttr "    flags" (show (seg_flags s))
  ++ concat (ppSection <$> seg_sections s)
ppLoadCommand c = show c ++ "\n"
