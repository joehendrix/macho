{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
module Data.MachoPure.Header
  ( -- * Header
    MachoHeader(..)
    -- ** Magic
  , MH_MAGIC
  , mkMagic
  , magicIs64Bit
  , magicIsLittleEndian
  , magicWordSize
  , pattern MH_MAGIC32
  , pattern MH_MAGIC64
  , pattern MH_CIGAM32
  , pattern MH_CIGAM64
    -- ** CPU type
  , CPU_TYPE(..)
  , pattern CPU_TYPE_64
  , pattern CPU_TYPE_X86
  , pattern CPU_TYPE_X86_64
  , pattern CPU_TYPE_ARM
  , pattern CPU_TYPE_POWERPC
  , pattern CPU_TYPE_POWERPC64
    -- ** CPU subtype
  , CPU_SUBTYPE(..)
    -- *** Intel subtypes
  , pattern  CPU_SUBTYPE_X86_64_ALL
  , pattern  CPU_SUBTYPE_X86_ARCH1
  , pattern  CPU_SUBTYPE_PENT
  , pattern  CPU_SUBTYPE_PENTIUM_3
  , pattern  CPU_SUBTYPE_PENTIUM_M
  , pattern  CPU_SUBTYPE_PENTIUM_4
  , pattern  CPU_SUBTYPE_ITANIUM
  , pattern  CPU_SUBTYPE_XEON
  , pattern  CPU_SUBTYPE_PENTPRO
  , pattern  CPU_SUBTYPE_PENTIUM_3_M
  , pattern  CPU_SUBTYPE_PENTIUM_4_M
  , pattern  CPU_SUBTYPE_ITANIUM_2
  , pattern  CPU_SUBTYPE_XEON_MP
  , pattern  CPU_SUBTYPE_PENTIUM_3_XEON
  , pattern  CPU_SUBTYPE_PENTII_M3
  , pattern  CPU_SUBTYPE_PENTII_M5
  , pattern  CPU_SUBTYPE_CELERON
  , pattern  CPU_SUBTYPE_CELERON_MOBILE
  , pattern  CPU_SUBTYPE_486SX
    -- *** ARM subtypes
  , pattern  CPU_SUBTYPE_ARM_ALL
  , pattern  CPU_SUBTYPE_ARM_V4T
  , pattern  CPU_SUBTYPE_ARM_V6
    -- *** PowerPC subtypes
  , pattern  CPU_SUBTYPE_POWERPC_ALL
  , pattern  CPU_SUBTYPE_POWERPC_601
  , pattern  CPU_SUBTYPE_POWERPC_602
  , pattern  CPU_SUBTYPE_POWERPC_603
  , pattern  CPU_SUBTYPE_POWERPC_603e
  , pattern  CPU_SUBTYPE_POWERPC_603ev
  , pattern  CPU_SUBTYPE_POWERPC_604
  , pattern  CPU_SUBTYPE_POWERPC_604e
  , pattern  CPU_SUBTYPE_POWERPC_620
  , pattern  CPU_SUBTYPE_POWERPC_750
  , pattern  CPU_SUBTYPE_POWERPC_7400
  , pattern  CPU_SUBTYPE_POWERPC_7450
  , pattern  CPU_SUBTYPE_POWERPC_970
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
  ) where

import           Data.Bits
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Word
import           Numeric (showHex)

-- | A magic value from a bytestring
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
--
-- This test is to check whether either the least or most-signifcant byte is odd.
magicIs64Bit :: MH_MAGIC -> Bool
magicIs64Bit (MH_MAGIC v) = v .&. 0x01000001 /= 0

-- | The word size for the given magic
magicWordSize :: MH_MAGIC -> Word32
magicWordSize m = if magicIs64Bit m then 8 else 4

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

newtype CPU_TYPE = CPU_TYPE { cpuTypeValue :: Word32 }
  deriving (Eq, Ord, Bits)
-- ^ Wrapper for recognizing CPU types.

-- | Pattern for recognizing 64-bit flag
pattern CPU_TYPE_64 :: CPU_TYPE
pattern CPU_TYPE_64 = CPU_TYPE 0x01000000

pattern CPU_TYPE_X86 :: CPU_TYPE
pattern CPU_TYPE_X86 = CPU_TYPE 0x07

pattern CPU_TYPE_X86_64 :: CPU_TYPE
pattern CPU_TYPE_X86_64 = CPU_TYPE 0x01000007

pattern CPU_TYPE_ARM :: CPU_TYPE
pattern CPU_TYPE_ARM = CPU_TYPE 0x0c

pattern CPU_TYPE_POWERPC :: CPU_TYPE
pattern CPU_TYPE_POWERPC = CPU_TYPE 0x12

pattern CPU_TYPE_POWERPC64 :: CPU_TYPE
pattern CPU_TYPE_POWERPC64 = CPU_TYPE 0x01000012

cputype :: Map CPU_TYPE String
cputype = Map.fromList
 [ (CPU_TYPE_X86,       "CPU_TYPE_X86")
 , (CPU_TYPE_X86_64,    "CPU_TYPE_X86_64")
 , (CPU_TYPE_ARM,       "CPU_TYPE_ARM")
 , (CPU_TYPE_POWERPC,   "CPU_TYPE_POWERPC")
 , (CPU_TYPE_POWERPC64, "CPU_TYPE_POWERPC64")
 ]

instance Show CPU_TYPE where
    show c =
      case Map.lookup c cputype of
        Just nm -> nm
        Nothing -> "0x" ++ showHex (cpuTypeValue c) ""

------------------------------------------------------------------------
-- CPU_SUBTYPE

newtype CPU_SUBTYPE = CPU_SUBTYPE Word32
  deriving (Eq, Ord, Show)

------------------------------------------------------------------------
-- CPU_SUBTYPE_X86

pattern  CPU_SUBTYPE_X86_64_ALL :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_X86_64_ALL = CPU_SUBTYPE 0x03

pattern  CPU_SUBTYPE_X86_ARCH1 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_X86_ARCH1 = CPU_SUBTYPE 0x04

pattern  CPU_SUBTYPE_PENT :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENT = CPU_SUBTYPE 0x05

pattern  CPU_SUBTYPE_PENTIUM_3 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTIUM_3 = CPU_SUBTYPE 0x08

pattern  CPU_SUBTYPE_PENTIUM_M :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTIUM_M = CPU_SUBTYPE 0x09

pattern  CPU_SUBTYPE_PENTIUM_4 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTIUM_4 = CPU_SUBTYPE 0x0A

pattern  CPU_SUBTYPE_ITANIUM :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_ITANIUM = CPU_SUBTYPE 0x0B

pattern  CPU_SUBTYPE_XEON :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_XEON = CPU_SUBTYPE 0x0C

pattern  CPU_SUBTYPE_PENTPRO :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTPRO = CPU_SUBTYPE 0x16

pattern  CPU_SUBTYPE_PENTIUM_3_M :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTIUM_3_M = CPU_SUBTYPE 0x18

pattern  CPU_SUBTYPE_PENTIUM_4_M :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTIUM_4_M = CPU_SUBTYPE 0x1A

pattern  CPU_SUBTYPE_ITANIUM_2 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_ITANIUM_2 = CPU_SUBTYPE 0x1B

pattern  CPU_SUBTYPE_XEON_MP :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_XEON_MP = CPU_SUBTYPE 0x1C

pattern  CPU_SUBTYPE_PENTIUM_3_XEON :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTIUM_3_XEON = CPU_SUBTYPE 0x28

pattern  CPU_SUBTYPE_PENTII_M3 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTII_M3 = CPU_SUBTYPE 0x36

pattern  CPU_SUBTYPE_PENTII_M5 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_PENTII_M5 = CPU_SUBTYPE 0x56

pattern  CPU_SUBTYPE_CELERON :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_CELERON = CPU_SUBTYPE 0x67

pattern  CPU_SUBTYPE_CELERON_MOBILE :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_CELERON_MOBILE = CPU_SUBTYPE 0x77

pattern  CPU_SUBTYPE_486SX :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_486SX = CPU_SUBTYPE 0x84

------------------------------------------------------------------------
-- CPU_SUBTYPE_POWERPC

pattern  CPU_SUBTYPE_POWERPC_ALL :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_ALL = CPU_SUBTYPE 0

pattern  CPU_SUBTYPE_POWERPC_601 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_601 = CPU_SUBTYPE 1

pattern  CPU_SUBTYPE_POWERPC_602 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_602 = CPU_SUBTYPE 2

pattern  CPU_SUBTYPE_POWERPC_603 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_603 = CPU_SUBTYPE 3

pattern  CPU_SUBTYPE_POWERPC_603e :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_603e = CPU_SUBTYPE 4

pattern  CPU_SUBTYPE_POWERPC_603ev :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_603ev = CPU_SUBTYPE 5

pattern  CPU_SUBTYPE_POWERPC_604 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_604 = CPU_SUBTYPE 6

pattern  CPU_SUBTYPE_POWERPC_604e :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_604e = CPU_SUBTYPE 7

pattern  CPU_SUBTYPE_POWERPC_620 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_620 = CPU_SUBTYPE 8

pattern  CPU_SUBTYPE_POWERPC_750 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_750 = CPU_SUBTYPE 9

pattern  CPU_SUBTYPE_POWERPC_7400 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_7400 = CPU_SUBTYPE 10

pattern  CPU_SUBTYPE_POWERPC_7450 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_7450 = CPU_SUBTYPE 11

pattern  CPU_SUBTYPE_POWERPC_970 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_POWERPC_970 = CPU_SUBTYPE 100

------------------------------------------------------------------------
-- CPU_SUBTYPE_ARM

pattern  CPU_SUBTYPE_ARM_ALL :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_ARM_ALL = CPU_SUBTYPE 0

pattern  CPU_SUBTYPE_ARM_V4T :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_ARM_V4T = CPU_SUBTYPE 5

pattern  CPU_SUBTYPE_ARM_V6 :: CPU_SUBTYPE
pattern  CPU_SUBTYPE_ARM_V6 = CPU_SUBTYPE  6

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
