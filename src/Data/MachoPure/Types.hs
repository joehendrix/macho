{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
module Data.MachoPure.Types
  ( Macho(..)
    -- * Header
  , MachoHeader(..)
    -- ** Magic
  , MH_MAGIC
  , mkMagic
  , magicIs64Bit
  , magicIsLittleEndian
  , pattern MH_MAGIC32
  , pattern MH_MAGIC64
  , pattern MH_CIGAM32
  , pattern MH_CIGAM64
    -- ** CPU type
  , CPU_TYPE(..)
  , mach_to_cputype
  , CPU_SUBTYPE(..)
  , mach_to_cpusubtype
    -- ** Filetype
  , MH_FILETYPE(..)
  , pattern MH_OBJECT
  , pattern MH_EXECUTE
  , pattern MH_CORE
  , pattern MH_PRELOAD
  , pattern MH_DYLIB
  , pattern MH_DYLINKER
  , pattern MH_BUNDLE
  , pattern MH_DYLIB_STUB
  , pattern MH_DSYM
  , pattern MH_KEXT_BUNDLE
    -- ** Header flags
  , MH_FLAGS(..)
  , pattern MH_NOUNDEFS
  , pattern MH_INCRLINK
  , pattern MH_DYLDLINK
  , pattern MH_BINDATLOAD
  , pattern MH_PREBOUND
  , pattern MH_SPLIT_SEGS
  , pattern MH_LAZY_INIT
  , pattern MH_TWOLEVEL
  , pattern MH_FORCE_FLAT
  , pattern MH_NOMULTIDEFS
  , pattern MH_NOFIXPREBINDING
  , pattern MH_PREBINDABLE
  , pattern MH_ALLMODSBOUND
  , pattern MH_SUBSECTIONS_VIA_SYMBOLS
  , pattern MH_CANONICAL
  , pattern MH_WEAK_DEFINES
  , pattern MH_BINDS_TO_WEAK
  , pattern MH_ALLOW_STACK_EXECUTION
  , pattern MH_ROOT_SAFE
  , pattern MH_SETUID_SAFE
  , pattern MH_NO_REEXPORTED_DYLIBS
  , pattern MH_PIE
  , pattern MH_DEAD_STRIPPABLE_DYLIB
  , pattern MH_HAS_TLV_DESCRIPTORS
  , pattern MH_NO_HEAP_EXECUTION
    -- * Commands
  , LC_COMMAND(..)
    -- * Segments
  , MachoSegment(..)
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
  , SectionName
  , getSectionName
    -- ** S_TYPE
  , S_TYPE(..)
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
    -- ** Section attributes
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
    -- * Symbols
  , MachoSymbol(..)
    -- ** Symbol type information
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
    -- ** REFERENCE_FLAG
  , REFERENCE_FLAG(..)
  , referenceType
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
    -- ** Library reference for two-level symbols
  , referenceLibraryOrdinal
  -- * Relocations
  , Relocation(..)
  , RelocationInfo(..)
  , ScatteredRelocationInfo(..)
  , R_TYPE(..)
  , r_type
    -- * Other
  , DylibModule(..)
  , MachoDynamicSymbolTable(..)
  ) where

import           Data.Bimap (Bimap)
import qualified Data.Bimap as Bimap
import           Data.Binary.Get hiding (Decoder)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import           Data.Int
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Monoid
import           Data.String
import           Data.Word
import           Numeric (showHex)

newtype MH_MAGIC = MH_MAGIC { magicValue :: Word32 }
  deriving (Eq, Ord)

pattern MH_MAGIC32 :: MH_MAGIC
pattern MH_MAGIC32 = MH_MAGIC 0xfeedface

pattern MH_CIGAM32 :: MH_MAGIC
pattern MH_CIGAM32 = MH_MAGIC 0xcefaedfe

pattern MH_MAGIC64 :: MH_MAGIC
pattern MH_MAGIC64 = MH_MAGIC 0xfeedfacf

pattern MH_CIGAM64 :: MH_MAGIC
pattern MH_CIGAM64 = MH_MAGIC 0xcffaedfe

-- | Check magic uses little endian byte order.
magicIsLittleEndian :: MH_MAGIC -> Bool
magicIsLittleEndian (MH_MAGIC v) = (v .&. 0xfeedface) == 0xfeedface

-- | Check magic is 64-bit
-- This test is to check whether either the least or most-signifcant byte is odd.
magicIs64Bit :: MH_MAGIC -> Bool
magicIs64Bit (MH_MAGIC v) = v .&. 0x01000001 /= 0

knownMagic :: Map MH_MAGIC String
knownMagic = Map.fromList
  [ (,) MH_MAGIC32 "MH_MAGIC32"
  , (,) MH_MAGIC64 "MH_MAGIC64"
  , (,) MH_CIGAM32 "MH_CIGAM32"
  , (,) MH_CIGAM64 "MH_CIGAM64"
  ]

-- | Create magic from Word32 read in little-bit endian order.
mkMagic :: Word32 -> Maybe MH_MAGIC
mkMagic w
  | Map.member (MH_MAGIC w) knownMagic = Just (MH_MAGIC w)
  | otherwise = Nothing

instance Show MH_MAGIC where
  show m =
    case Map.lookup m knownMagic of
      Just nm -> nm
      Nothing -> "0x" ++ showHex (magicValue m) ""

------------------------------------------------------------------------
-- CPU_TYPE

data CPU_TYPE
    = CPU_TYPE_X86
    | CPU_TYPE_X86_64
    | CPU_TYPE_ARM
    | CPU_TYPE_POWERPC
    | CPU_TYPE_POWERPC64
    deriving (Ord, Show, Eq, Enum)

cputype :: Map Word32 CPU_TYPE
cputype = Map.fromList
 [ (0x00000007, CPU_TYPE_X86)
 , (0x01000007, CPU_TYPE_X86_64)
 , (0x0000000c, CPU_TYPE_ARM)
 , (0x00000012, CPU_TYPE_POWERPC)
 , (0x01000012, CPU_TYPE_POWERPC64)
 ]

mach_to_cputype :: Word32 -> Maybe CPU_TYPE
mach_to_cputype w = Map.lookup w cputype

data CPU_SUBTYPE
    = CPU_SUBTYPE_INTEL
    | CPU_SUBTYPE_I386_ALL
    | CPU_SUBTYPE_386
    | CPU_SUBTYPE_486
    | CPU_SUBTYPE_486SX
    | CPU_SUBTYPE_PENT
    | CPU_SUBTYPE_PENTPRO
    | CPU_SUBTYPE_PENTII_M3
    | CPU_SUBTYPE_PENTII_M5
    | CPU_SUBTYPE_CELERON
    | CPU_SUBTYPE_CELERON_MOBILE
    | CPU_SUBTYPE_PENTIUM_3
    | CPU_SUBTYPE_PENTIUM_3_M
    | CPU_SUBTYPE_PENTIUM_3_XEON
    | CPU_SUBTYPE_PENTIUM_M
    | CPU_SUBTYPE_PENTIUM_4
    | CPU_SUBTYPE_PENTIUM_4_M
    | CPU_SUBTYPE_ITANIUM
    | CPU_SUBTYPE_ITANIUM_2
    | CPU_SUBTYPE_XEON
    | CPU_SUBTYPE_XEON_MP
    | CPU_SUBTYPE_INTEL_FAMILY
    | CPU_SUBTYPE_INTEL_FAMILY_MAX
    | CPU_SUBTYPE_INTEL_MODEL
    | CPU_SUBTYPE_INTEL_MODEL_ALL
    | CPU_SUBTYPE_X86_ALL
    | CPU_SUBTYPE_X86_64_ALL
    | CPU_SUBTYPE_X86_ARCH1
    | CPU_SUBTYPE_POWERPC_ALL
    | CPU_SUBTYPE_POWERPC_601
    | CPU_SUBTYPE_POWERPC_602
    | CPU_SUBTYPE_POWERPC_603
    | CPU_SUBTYPE_POWERPC_603e
    | CPU_SUBTYPE_POWERPC_603ev
    | CPU_SUBTYPE_POWERPC_604
    | CPU_SUBTYPE_POWERPC_604e
    | CPU_SUBTYPE_POWERPC_620
    | CPU_SUBTYPE_POWERPC_750
    | CPU_SUBTYPE_POWERPC_7400
    | CPU_SUBTYPE_POWERPC_7450
    | CPU_SUBTYPE_POWERPC_970
    | CPU_SUBTYPE_ARM_ALL
    | CPU_SUBTYPE_ARM_V4T
    | CPU_SUBTYPE_ARM_V6
    deriving (Ord, Show, Eq, Enum)

cpusubtype :: Bimap (CPU_TYPE, Word32) CPU_SUBTYPE
cpusubtype = Bimap.fromList
  [ ((CPU_TYPE_X86, 132)      , CPU_SUBTYPE_486SX)
  , ((CPU_TYPE_X86, 5)        , CPU_SUBTYPE_PENT)
  , ((CPU_TYPE_X86, 22)       , CPU_SUBTYPE_PENTPRO)
  , ((CPU_TYPE_X86, 54)       , CPU_SUBTYPE_PENTII_M3)
  , ((CPU_TYPE_X86, 86)       , CPU_SUBTYPE_PENTII_M5)
  , ((CPU_TYPE_X86, 103)      , CPU_SUBTYPE_CELERON)
  , ((CPU_TYPE_X86, 119)      , CPU_SUBTYPE_CELERON_MOBILE)
  , ((CPU_TYPE_X86, 8)        , CPU_SUBTYPE_PENTIUM_3)
  , ((CPU_TYPE_X86, 24)       , CPU_SUBTYPE_PENTIUM_3_M)
  , ((CPU_TYPE_X86, 40)       , CPU_SUBTYPE_PENTIUM_3_XEON)
  , ((CPU_TYPE_X86, 9)        , CPU_SUBTYPE_PENTIUM_M)
  , ((CPU_TYPE_X86, 10)       , CPU_SUBTYPE_PENTIUM_4)
  , ((CPU_TYPE_X86, 26)       , CPU_SUBTYPE_PENTIUM_4_M)
  , ((CPU_TYPE_X86, 11)       , CPU_SUBTYPE_ITANIUM)
  , ((CPU_TYPE_X86, 27)       , CPU_SUBTYPE_ITANIUM_2)
  , ((CPU_TYPE_X86, 12)       , CPU_SUBTYPE_XEON)
  , ((CPU_TYPE_X86, 28)       , CPU_SUBTYPE_XEON_MP)
  , ((CPU_TYPE_X86, 3)        , CPU_SUBTYPE_X86_ALL)
  , ((CPU_TYPE_X86, 4)        , CPU_SUBTYPE_X86_ARCH1)
  , ((CPU_TYPE_X86_64, 3)     , CPU_SUBTYPE_X86_64_ALL)
  , ((CPU_TYPE_POWERPC, 0)    , CPU_SUBTYPE_POWERPC_ALL)
  , ((CPU_TYPE_POWERPC, 1)    , CPU_SUBTYPE_POWERPC_601)
  , ((CPU_TYPE_POWERPC, 2)    , CPU_SUBTYPE_POWERPC_602)
  , ((CPU_TYPE_POWERPC, 3)    , CPU_SUBTYPE_POWERPC_603)
  , ((CPU_TYPE_POWERPC, 4)    , CPU_SUBTYPE_POWERPC_603e)
  , ((CPU_TYPE_POWERPC, 5)    , CPU_SUBTYPE_POWERPC_603ev)
  , ((CPU_TYPE_POWERPC, 6)    , CPU_SUBTYPE_POWERPC_604)
  , ((CPU_TYPE_POWERPC, 7)    , CPU_SUBTYPE_POWERPC_604e)
  , ((CPU_TYPE_POWERPC, 8)    , CPU_SUBTYPE_POWERPC_620)
  , ((CPU_TYPE_POWERPC, 9)    , CPU_SUBTYPE_POWERPC_750)
  , ((CPU_TYPE_POWERPC, 10)   , CPU_SUBTYPE_POWERPC_7400)
  , ((CPU_TYPE_POWERPC, 11)   , CPU_SUBTYPE_POWERPC_7450)
  , ((CPU_TYPE_POWERPC, 100)  , CPU_SUBTYPE_POWERPC_970)
  , ((CPU_TYPE_POWERPC64, 0)  , CPU_SUBTYPE_POWERPC_ALL)
  , ((CPU_TYPE_POWERPC64, 1)  , CPU_SUBTYPE_POWERPC_601)
  , ((CPU_TYPE_POWERPC64, 2)  , CPU_SUBTYPE_POWERPC_602)
  , ((CPU_TYPE_POWERPC64, 3)  , CPU_SUBTYPE_POWERPC_603)
  , ((CPU_TYPE_POWERPC64, 4)  , CPU_SUBTYPE_POWERPC_603e)
  , ((CPU_TYPE_POWERPC64, 5)  , CPU_SUBTYPE_POWERPC_603ev)
  , ((CPU_TYPE_POWERPC64, 6)  , CPU_SUBTYPE_POWERPC_604)
  , ((CPU_TYPE_POWERPC64, 7)  , CPU_SUBTYPE_POWERPC_604e)
  , ((CPU_TYPE_POWERPC64, 8)  , CPU_SUBTYPE_POWERPC_620)
  , ((CPU_TYPE_POWERPC64, 9)  , CPU_SUBTYPE_POWERPC_750)
  , ((CPU_TYPE_POWERPC64, 10) , CPU_SUBTYPE_POWERPC_7400)
  , ((CPU_TYPE_POWERPC64, 11) , CPU_SUBTYPE_POWERPC_7450)
  , ((CPU_TYPE_POWERPC64, 100), CPU_SUBTYPE_POWERPC_970)
  , ((CPU_TYPE_ARM, 0)        , CPU_SUBTYPE_ARM_ALL)
  , ((CPU_TYPE_ARM, 5)        , CPU_SUBTYPE_ARM_V4T)
  , ((CPU_TYPE_ARM, 6)        , CPU_SUBTYPE_ARM_V6)
  ]

mach_to_cpusubtype :: CPU_TYPE -> Word32 -> CPU_SUBTYPE
mach_to_cpusubtype = curry (cpusubtype Bimap.!)

------------------------------------------------------------------------
-- MH_FILETYPE

newtype MH_FILETYPE = MH_FILETYPE { mhFiletypeCode :: Word32 }
  deriving (Eq, Ord)

pattern MH_OBJECT :: MH_FILETYPE
pattern MH_OBJECT = MH_FILETYPE 0x1
-- ^ relocatable object file

pattern MH_EXECUTE :: MH_FILETYPE
pattern MH_EXECUTE = MH_FILETYPE 0x2
-- ^ demand paged executable file

pattern MH_CORE :: MH_FILETYPE
pattern MH_CORE = MH_FILETYPE 0x4
-- ^ core file

pattern MH_PRELOAD :: MH_FILETYPE
pattern MH_PRELOAD = MH_FILETYPE 0x5
-- ^ preloaded executable file

pattern MH_DYLIB :: MH_FILETYPE
pattern MH_DYLIB = MH_FILETYPE 0x6
-- ^ dynamically bound shared library

pattern MH_DYLINKER :: MH_FILETYPE
pattern MH_DYLINKER = MH_FILETYPE 0x7
-- ^ dynamic link editor

pattern MH_BUNDLE :: MH_FILETYPE
pattern MH_BUNDLE = MH_FILETYPE 0x8
-- ^ dynamically bound bundle file

pattern MH_DYLIB_STUB :: MH_FILETYPE
pattern MH_DYLIB_STUB = MH_FILETYPE 0x9
-- ^ shared library stub for static. linking only, no section contents

pattern MH_DSYM :: MH_FILETYPE
pattern MH_DSYM = MH_FILETYPE 0xa
-- ^ companion file with only debug. sections

pattern MH_KEXT_BUNDLE :: MH_FILETYPE
pattern MH_KEXT_BUNDLE = MH_FILETYPE 0xb

-- | Map from filetypes to string for known filetypes.
knownFiletypes :: Map MH_FILETYPE String
knownFiletypes = Map.fromList
  [ (,) MH_OBJECT "MH_OBJECT"
  , (,) MH_EXECUTE "MH_EXECUTE"
  , (,) MH_CORE "MH_CORE"
  , (,) MH_PRELOAD "MH_PRELOAD"
  , (,) MH_DYLIB "MH_DYLIB"
  , (,) MH_DYLINKER "MH_DYLINKER"
  , (,) MH_BUNDLE "MH_BUNDLE"
  , (,) MH_DYLIB_STUB "MH_DYLIB_STUB"
  , (,) MH_DSYM "MH_DSYM"
  , (,) MH_KEXT_BUNDLE "MH_KEXT_BUNDLE"
  ]

instance Show MH_FILETYPE where
  show tp =
    case Map.lookup tp knownFiletypes of
      Just nm -> nm
      Nothing -> "MH_UNKNOWN " ++ showHex (mhFiletypeCode tp) ""

------------------------------------------------------------------------
-- MH_FLAGS

-- | Flags in the header
newtype MH_FLAGS = MH_FLAGS Word32
  deriving (Eq, Bits)

instance Show MH_FLAGS where
  show (MH_FLAGS x) = "0x" ++ showHex x ""

pattern MH_NOUNDEFS :: MH_FLAGS
pattern MH_NOUNDEFS = MH_FLAGS 0x0001
-- ^ the object file has no undefined references

pattern MH_INCRLINK :: MH_FLAGS
pattern MH_INCRLINK = MH_FLAGS 0x0002
-- ^ the object file is the output of an incremental link against a
-- base file and can't be link edited again

pattern MH_DYLDLINK :: MH_FLAGS
pattern MH_DYLDLINK = MH_FLAGS 0x0004
-- ^ the object file is input for the dynamic linker and can't be
-- staticly link edited again

pattern MH_BINDATLOAD :: MH_FLAGS
pattern MH_BINDATLOAD = MH_FLAGS 0x0008
-- ^ the object file's undefined references are bound by the dynamic
-- linker when loaded.

pattern MH_PREBOUND :: MH_FLAGS
pattern MH_PREBOUND = MH_FLAGS 0x0010
-- ^ the file has its dynamic undefined references prebound.

pattern MH_SPLIT_SEGS :: MH_FLAGS
pattern MH_SPLIT_SEGS = MH_FLAGS 0x0020
-- ^ the file has its read-only and read-write segments split

pattern MH_LAZY_INIT :: MH_FLAGS
pattern MH_LAZY_INIT = MH_FLAGS 0x0040

pattern MH_TWOLEVEL :: MH_FLAGS
pattern MH_TWOLEVEL = MH_FLAGS 0x0080
-- ^ the image is using two-level name space bindings

pattern MH_FORCE_FLAT :: MH_FLAGS
pattern MH_FORCE_FLAT = MH_FLAGS 0x0100
    -- ^ the executable is forcing all images to use flat name space bindings

pattern MH_NOMULTIDEFS :: MH_FLAGS
pattern MH_NOMULTIDEFS = MH_FLAGS 0x0200
-- ^ this umbrella guarantees no multiple defintions of symbols in its
-- sub-images so the two-level namespace hints can always be used.

pattern MH_NOFIXPREBINDING :: MH_FLAGS
pattern MH_NOFIXPREBINDING = MH_FLAGS 0x0400
-- ^ do not have dyld notify the prebinding agent about this
-- executable

pattern MH_PREBINDABLE :: MH_FLAGS
pattern MH_PREBINDABLE = MH_FLAGS 0x0800
-- ^ the binary is not prebound but can have its prebinding
-- redone. only used when MH_PREBOUND is not set.

pattern MH_ALLMODSBOUND :: MH_FLAGS
pattern MH_ALLMODSBOUND = MH_FLAGS 0x1000
-- ^ indicates that this binary binds to all two-level namespace
-- modules of its dependent libraries. only used when MH_PREBINDABLE
-- and MH_TWOLEVEL are both set.

pattern MH_SUBSECTIONS_VIA_SYMBOLS :: MH_FLAGS
pattern MH_SUBSECTIONS_VIA_SYMBOLS = MH_FLAGS 0x2000
-- ^ safe to divide up the sections into sub-sections via symbols for
-- dead code stripping

pattern MH_CANONICAL :: MH_FLAGS
pattern MH_CANONICAL = MH_FLAGS 0x4000
-- ^ the binary has been canonicalized via the unprebind operation

pattern MH_WEAK_DEFINES :: MH_FLAGS
pattern MH_WEAK_DEFINES = MH_FLAGS 0x8000
-- ^ the final linked image contains external weak symbols

pattern MH_BINDS_TO_WEAK :: MH_FLAGS
pattern MH_BINDS_TO_WEAK = MH_FLAGS 0x010000
-- ^ the final linked image uses weak symbols

pattern MH_ALLOW_STACK_EXECUTION :: MH_FLAGS
pattern MH_ALLOW_STACK_EXECUTION = MH_FLAGS 0x020000
-- ^ When this bit is set, all stacks in the task will be given stack
-- execution privilege.  Only used in MH_EXECUTE filetypes.

pattern MH_ROOT_SAFE :: MH_FLAGS
pattern MH_ROOT_SAFE = MH_FLAGS 0x040000
-- ^ When this bit is set, the binary declares it is safe for use in
-- processes with uid zero

pattern MH_SETUID_SAFE :: MH_FLAGS
pattern MH_SETUID_SAFE = MH_FLAGS 0x080000
-- ^ When this bit is set, the binary de clares it is safe for use in
-- processes when issetugid() is true

pattern MH_NO_REEXPORTED_DYLIBS :: MH_FLAGS
pattern MH_NO_REEXPORTED_DYLIBS = MH_FLAGS 0x100000
-- ^ When this bit is set on a dylib, the static linker does not need
-- to examine dependent dylibs to see if any are re-exported

pattern MH_PIE :: MH_FLAGS
pattern MH_PIE = MH_FLAGS 0x200000
-- ^ When this bit is set, the OS will load the main executable at a
-- random address.  Only used in MH_EXECUTE filetypes.

pattern MH_DEAD_STRIPPABLE_DYLIB :: MH_FLAGS
pattern MH_DEAD_STRIPPABLE_DYLIB = MH_FLAGS 0x400000
-- ^ Only for use on dylibs.  When linking against a dylib that has
-- this bit set, the static linker will automatically not create a
-- LC_LOAD_DYLIB load command to the dylib if no symbols are being
-- referenced from the dylib.

pattern MH_HAS_TLV_DESCRIPTORS :: MH_FLAGS
pattern MH_HAS_TLV_DESCRIPTORS = MH_FLAGS 0x800000
-- ^ Contains a section of type S_THREAD_LOCAL_VARIABLES

pattern MH_NO_HEAP_EXECUTION :: MH_FLAGS
pattern MH_NO_HEAP_EXECUTION = MH_FLAGS 0x1000000
-- ^ When this bit is set, the OS will run the main executable with a
-- non-executable heap even on platforms (e.g. i386) that don't
-- require it. Only used in MH_EXECUTE filetypes.

------------------------------------------------------------------------
-- MachoHeader

data MachoHeader = MachoHeader
    { mh_magic      :: !MH_MAGIC
    , mh_cputype    :: !CPU_TYPE    -- ^ CPU family the Mach-O executes on.
    , mh_cpusubtype :: !CPU_SUBTYPE -- ^ Specific CPU type the Mach-O executes on.
    , mh_filetype   :: !MH_FILETYPE -- ^ Type of Mach-o file.
    , mh_flags      :: !MH_FLAGS  -- ^ Flags.
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- SegmentName

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
-- S_TYPE

newtype S_TYPE = S_TYPE Word8
  deriving (Eq,Show)

pattern S_REGULAR :: S_TYPE
pattern S_REGULAR = S_TYPE 0x00
-- ^ regular section

pattern S_ZEROFILL :: S_TYPE
pattern S_ZEROFILL = S_TYPE 0x01
-- ^ zero fill on demand section

pattern S_CSTRING_LITERALS :: S_TYPE
pattern S_CSTRING_LITERALS = S_TYPE 0x02
-- ^ section with only literal C strings

pattern S_4BYTE_LITERALS :: S_TYPE
pattern S_4BYTE_LITERALS = S_TYPE 0x03
-- ^ section with only 4 byte literals

pattern S_8BYTE_LITERALS :: S_TYPE
pattern S_8BYTE_LITERALS = S_TYPE 0x04
-- ^ section with only 8 byte literals

pattern S_LITERAL_POINTERS :: S_TYPE
pattern S_LITERAL_POINTERS = S_TYPE 0x05
-- ^ section with only pointers to literals

pattern S_NON_LAZY_SYMBOL_POINTERS :: S_TYPE
pattern S_NON_LAZY_SYMBOL_POINTERS = S_TYPE 0x06
-- ^ section with only non-lazy symbol pointers

pattern S_LAZY_SYMBOL_POINTERS :: S_TYPE
pattern S_LAZY_SYMBOL_POINTERS = S_TYPE 0x07
-- ^ section with only lazy symbol pointers

pattern S_SYMBOL_STUBS :: S_TYPE
pattern S_SYMBOL_STUBS = S_TYPE 0x08
-- ^ section with only symbol stubs, bte size of stub in the reserved2 field

pattern S_MOD_INIT_FUNC_POINTERS :: S_TYPE
pattern S_MOD_INIT_FUNC_POINTERS = S_TYPE 0x09
-- ^ section with only function pointers for initialization

pattern S_MOD_TERM_FUNC_POINTERS :: S_TYPE
pattern S_MOD_TERM_FUNC_POINTERS = S_TYPE 0x0a
-- ^ section with only function pointers for termination

pattern S_COALESCED :: S_TYPE
pattern S_COALESCED = S_TYPE 0x0b
-- ^ section contains symbols that are to be coalesced

pattern S_GB_ZEROFILL :: S_TYPE
pattern S_GB_ZEROFILL = S_TYPE 0x0c
-- ^ zero fill on demand section (that can be larger than 4 gigabytes)

pattern S_INTERPOSING :: S_TYPE
pattern S_INTERPOSING = S_TYPE 0x0d
-- ^ section with only pairs of function pointers for interposing

pattern S_16BYTE_LITERALS :: S_TYPE
pattern S_16BYTE_LITERALS = S_TYPE 0x0e
-- ^ section with only 16 byte literals

pattern S_DTRACE_DOF :: S_TYPE
pattern S_DTRACE_DOF = S_TYPE 0x0f
-- ^ section contains DTrace Object Format

pattern S_LAZY_DYLIB_SYMBOL_POINTERS :: S_TYPE
pattern S_LAZY_DYLIB_SYMBOL_POINTERS = S_TYPE 0x10
-- ^ section with only lazy symbol pointers to lazy loaded dylibs

------------------------------------------------------------------------
-- S_ATTR

newtype S_ATTR = S_ATTR Word32
  deriving (Eq, Bits, Num)

instance Show S_ATTR where
  show (S_ATTR x) = "0x" ++ showHex x ""

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

data MachoSection = MachoSection
    { sec_sectname :: !SectionName
      -- ^ name of section
    , sec_segname  :: !SegmentName        -- ^ name of segment that should own this section
    , sec_addr     :: !Word64        -- ^ virtual memoy address for section
    , sec_size     :: !Word64        -- ^ size of section
    , sec_align    :: !Int
      -- ^ alignment required by section (literal form, not power of two, e.g. 8 not 3)
    , sec_relocs   :: ![Relocation]  -- ^ relocations for this section
    , sec_type     :: !S_TYPE        -- ^ type of section
    , sec_attrs    :: !S_ATTR        -- ^ attributes of section
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- VM_PROT

-- | Protection flags for memory
newtype VM_PROT = VM_PROT { vmProtValue :: Word32 }
  deriving (Eq, Bits)

instance Show VM_PROT where
  show p
    | p .&. VM_PROT 0x7 == p =
      let checkBit :: VM_PROT -> String -> String
          checkBit m s = if p .&. m == m then s else ""
       in checkBit VM_PROT_EXECUTE "x"
       ++ checkBit VM_PROT_WRITE   "w"
       ++ checkBit VM_PROT_READ    "r"
    | otherwise = "VM_PROT " ++ showHex (vmProtValue p) ""

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


data MachoSegment = MachoSegment
    { seg_segname  :: !SegmentName    -- ^ segment name
    , seg_vmaddr   :: !Word64         -- ^ virtual address where the segment is loaded
    , seg_vmsize   :: !Word64         -- ^ size of segment at runtime
    , seg_fileoff  :: !Word64         -- ^ file offset of the segment
    , seg_filesize :: !Word64         -- ^ size of segment in file
    , seg_maxprot  :: !VM_PROT        -- ^ maximum virtual memory protection
    , seg_initprot :: !VM_PROT        -- ^ initial virtual memory protection
    , seg_flags    :: !SG_FLAGS       -- ^ segment flags
    , seg_sections :: ![MachoSection] -- ^ sections owned by this segment
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- LC_COMMAND

data LC_COMMAND
    = LC_SEGMENT MachoSegment
      -- ^ segment of this file to be mapped
    | LC_SYMTAB [MachoSymbol] B.ByteString
      -- ^ static link-edit symbol table and stab info
    | LC_SYMSEG
    | LC_THREAD [(Word32, [Word32])]
      -- ^ thread state information (list of (flavor, [long]) pairs)
    | LC_UNIXTHREAD [(Word32, [Word32])]
      -- ^ unix thread state information (includes a stack) (list of (flavor, [long] pairs)
    | LC_LOADFVMLIB
    | LC_IDFVMLIB
    | LC_IDENT
    | LC_FVMFILE
    | LC_PREPAGE
    | LC_DYSYMTAB MachoDynamicSymbolTable
      -- ^ dynamic link-edit symbol table info
    | LC_LOAD_DYLIB String Word32 Word32 Word32
      -- ^ load a dynamically linked shared library (name, timestamp, current version, compatibility version)
    | LC_ID_DYLIB String Word32 Word32 Word32
      -- ^ dynamically linked shared lib ident (name, timestamp, current version, compatibility version)
    | LC_LOAD_DYLINKER String
      -- ^ load a dynamic linker (name of dynamic linker)
    | LC_ID_DYLINKER String
      -- ^ dynamic linker identification (name of dynamic linker)
    | LC_PREBOUND_DYLIB String [Word8]
      -- ^ modules prebound for a dynamically linked shared library (name, list of module indices)
    | LC_ROUTINES Word32 Word32
      -- ^ image routines (virtual address of initialization routine, module index where it resides)
    | LC_SUB_FRAMEWORK String
      -- ^ sub framework (name)
    | LC_SUB_UMBRELLA String
      -- ^ sub umbrella (name)
    | LC_SUB_CLIENT String
      -- ^ sub client (name)
    | LC_SUB_LIBRARY String
      -- ^ sub library (name)
    | LC_TWOLEVEL_HINTS [(Word32, Word32)]
      -- ^ two-level namespace lookup hints (list of (subimage index, symbol table index) pairs
    | LC_PREBIND_CKSUM Word32
      -- ^ prebind checksum (checksum)

    | LC_LOAD_WEAK_DYLIB String Word32 Word32 Word32
      -- ^ load a dynamically linked shared library that is allowed to be missing (symbols are weak imported) (name, timestamp, current version, compatibility version)
    | LC_SEGMENT_64 MachoSegment
      -- ^ 64-bit segment of this file to mapped
    | LC_ROUTINES_64 Word64 Word64
      -- ^ 64-bit image routines (virtual address of initialization routine, module index where it resides)
    | LC_UUID [Word8]
      -- ^ the uuid for an image or its corresponding dsym file (8 element list of bytes)
    | LC_RPATH String
      -- ^ runpath additions (path)
    | LC_CODE_SIGNATURE Word32 Word32
      -- ^ local of code signature
    | LC_SEGMENT_SPLIT_INFO Word32 Word32
      -- ^ local of info to split segments
    | LC_REEXPORT_DYLIB
    | LC_LAZY_LOAD_DYLIB
    | LC_ENCRYPTION_INFO !Word32 !B.ByteString
    | LC_DYLD_INFO
    | LC_DYLD_INFO_ONLY

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

------------------------------------------------------------------------
-- Macho

data Macho = Macho
    { m_header   :: MachoHeader  -- ^ Header information.
    , m_commands :: [LC_COMMAND] -- ^ List of load commands describing Mach-O contents.
    } deriving (Show, Eq)

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
  show (REFERENCE_FLAG w) = "REFERNCE_FLAG " ++ showHex w ""

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
 -- ^ indicates the symbol is a weak definition, will be overridden by a strong definition at link-time

------------------------------------------------------------------------
-- MachoSymbol

data MachoSymbol = MachoSymbol
    { sym_name  :: !B.ByteString -- ^ symbol name
    , sym_type  :: !SymbolType -- ^ symbol type
    , sym_sect  :: Word8                          -- ^ section index where the symbol can be found
    , sym_flags :: Either Word16 REFERENCE_FLAG -- ^ for stab entries, Left Word16 is the uninterpreted flags field, otherwise Right REFERENCE_FLAG describes the symbol flags.
    , sym_value :: Word64                         -- ^ symbol value, 32-bit symbol values are promoted to 64-bit for simpliciy
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- Other

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

-- | Platform-specific relocation types.
data R_TYPE
    = GENERIC_RELOC_VANILLA
    | GENERIC_RELOC_PAIR
    | GENERIC_RELOC_SECTDIFF
    | GENERIC_RELOC_LOCAL_SECTDIFF
    | GENERIC_RELOC_PB_LA_PTR
    | ARM_RELOC_VANILLA
    | ARM_RELOC_PAIR
    | ARM_RELOC_SECTDIFF
    | ARM_RELOC_LOCAL_SECTDIFF
    | ARM_RELOC_PB_LA_PTR
    | ARM_RELOC_BR24
    | ARM_THUMB_RELOC_BR22
    | X86_64_RELOC_BRANCH
    | X86_64_RELOC_GOT_LOAD
    | X86_64_RELOC_GOT
    | X86_64_RELOC_SIGNED
    | X86_64_RELOC_UNSIGNED
    | X86_64_RELOC_SUBTRACTOR
    | X86_64_RELOC_SIGNED_1
    | X86_64_RELOC_SIGNED_2
    | X86_64_RELOC_SIGNED_4
    | PPC_RELOC_VANILLA
    | PPC_RELOC_PAIR
    | PPC_RELOC_BR14
    | PPC_RELOC_BR24
    | PPC_RELOC_HI16
    | PPC_RELOC_LO16
    | PPC_RELOC_HA16
    | PPC_RELOC_LO14
    | PPC_RELOC_SECTDIFF
    | PPC_RELOC_LOCAL_SECTDIFF
    | PPC_RELOC_PB_LA_PTR
    | PPC_RELOC_HI16_SECTDIFF
    | PPC_RELOC_LO16_SECTDIFF
    | PPC_RELOC_HA16_SECTDIFF
    | PPC_RELOC_JBSR
    | PPC_RELOC_LO14_SECTDIFF
    deriving (Ord, Show, Eq, Enum)


r_type :: Word32 -> CPU_TYPE -> Maybe R_TYPE
r_type 0 CPU_TYPE_X86        = Just GENERIC_RELOC_VANILLA
r_type 1 CPU_TYPE_X86        = Just GENERIC_RELOC_PAIR
r_type 2 CPU_TYPE_X86        = Just GENERIC_RELOC_SECTDIFF
r_type 3 CPU_TYPE_X86        = Just GENERIC_RELOC_LOCAL_SECTDIFF
r_type 4 CPU_TYPE_X86        = Just GENERIC_RELOC_PB_LA_PTR
r_type 0 CPU_TYPE_ARM        = Just ARM_RELOC_VANILLA
r_type 1 CPU_TYPE_ARM        = Just ARM_RELOC_PAIR
r_type 2 CPU_TYPE_ARM        = Just ARM_RELOC_SECTDIFF
r_type 3 CPU_TYPE_ARM        = Just ARM_RELOC_LOCAL_SECTDIFF
r_type 4 CPU_TYPE_ARM        = Just ARM_RELOC_PB_LA_PTR
r_type 5 CPU_TYPE_ARM        = Just ARM_RELOC_BR24
r_type 6 CPU_TYPE_ARM        = Just ARM_THUMB_RELOC_BR22
r_type 0 CPU_TYPE_X86_64     = Just X86_64_RELOC_UNSIGNED
r_type 1 CPU_TYPE_X86_64     = Just X86_64_RELOC_SIGNED
r_type 2 CPU_TYPE_X86_64     = Just X86_64_RELOC_BRANCH
r_type 3 CPU_TYPE_X86_64     = Just X86_64_RELOC_GOT_LOAD
r_type 4 CPU_TYPE_X86_64     = Just X86_64_RELOC_GOT
r_type 5 CPU_TYPE_X86_64     = Just X86_64_RELOC_SUBTRACTOR
r_type 6 CPU_TYPE_X86_64     = Just X86_64_RELOC_SIGNED_1
r_type 7 CPU_TYPE_X86_64     = Just X86_64_RELOC_SIGNED_2
r_type 8 CPU_TYPE_X86_64     = Just X86_64_RELOC_SIGNED_4
r_type 0 CPU_TYPE_POWERPC    = Just PPC_RELOC_VANILLA
r_type 1 CPU_TYPE_POWERPC    = Just PPC_RELOC_PAIR
r_type 2 CPU_TYPE_POWERPC    = Just PPC_RELOC_BR14
r_type 3 CPU_TYPE_POWERPC    = Just PPC_RELOC_BR24
r_type 4 CPU_TYPE_POWERPC    = Just PPC_RELOC_HI16
r_type 5 CPU_TYPE_POWERPC    = Just PPC_RELOC_LO16
r_type 6 CPU_TYPE_POWERPC    = Just PPC_RELOC_HA16
r_type 7 CPU_TYPE_POWERPC    = Just PPC_RELOC_LO14
r_type 8 CPU_TYPE_POWERPC    = Just PPC_RELOC_SECTDIFF
r_type 9 CPU_TYPE_POWERPC    = Just PPC_RELOC_PB_LA_PTR
r_type 10 CPU_TYPE_POWERPC   = Just PPC_RELOC_HI16_SECTDIFF
r_type 11 CPU_TYPE_POWERPC   = Just PPC_RELOC_LO16_SECTDIFF
r_type 12 CPU_TYPE_POWERPC   = Just PPC_RELOC_HA16_SECTDIFF
r_type 13 CPU_TYPE_POWERPC   = Just PPC_RELOC_JBSR
r_type 14 CPU_TYPE_POWERPC   = Just PPC_RELOC_LO14_SECTDIFF
r_type 15 CPU_TYPE_POWERPC   = Just PPC_RELOC_LOCAL_SECTDIFF
r_type 0 CPU_TYPE_POWERPC64  = Just PPC_RELOC_VANILLA
r_type 1 CPU_TYPE_POWERPC64  = Just PPC_RELOC_PAIR
r_type 2 CPU_TYPE_POWERPC64  = Just PPC_RELOC_BR14
r_type 3 CPU_TYPE_POWERPC64  = Just PPC_RELOC_BR24
r_type 4 CPU_TYPE_POWERPC64  = Just PPC_RELOC_HI16
r_type 5 CPU_TYPE_POWERPC64  = Just PPC_RELOC_LO16
r_type 6 CPU_TYPE_POWERPC64  = Just PPC_RELOC_HA16
r_type 7 CPU_TYPE_POWERPC64  = Just PPC_RELOC_LO14
r_type 8 CPU_TYPE_POWERPC64  = Just PPC_RELOC_SECTDIFF
r_type 9 CPU_TYPE_POWERPC64  = Just PPC_RELOC_PB_LA_PTR
r_type 10 CPU_TYPE_POWERPC64 = Just PPC_RELOC_HI16_SECTDIFF
r_type 11 CPU_TYPE_POWERPC64 = Just PPC_RELOC_LO16_SECTDIFF
r_type 12 CPU_TYPE_POWERPC64 = Just PPC_RELOC_HA16_SECTDIFF
r_type 13 CPU_TYPE_POWERPC64 = Just PPC_RELOC_JBSR
r_type 14 CPU_TYPE_POWERPC64 = Just PPC_RELOC_LO14_SECTDIFF
r_type 15 CPU_TYPE_POWERPC64 = Just PPC_RELOC_LOCAL_SECTDIFF
r_type _ _ = Nothing

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

data MachoDynamicSymbolTable = MachoDynamicSymbolTable
    { localSyms    :: (Word32, Word32)   -- ^ symbol table index and count for local symbols
    , extDefSyms   :: (Word32, Word32)   -- ^ symbol table index and count for externally defined symbols
    , undefSyms    :: (Word32, Word32)   -- ^ symbol table index and count for undefined symbols
    , tocEntries   :: [(Word32, Word32)] -- ^ list of symbol index and module index pairs
    , modules      :: [DylibModule]      -- ^ modules
    , extRefSyms   :: [Word32]           -- ^ list of external reference symbol indices
    , indirectSyms :: [Word32]           -- ^ list of indirect symbol indices
    , extRels      :: [Relocation]       -- ^ external locations
    , locRels      :: [Relocation]       -- ^ local relocations
    } deriving (Show, Eq)
