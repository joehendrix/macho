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
  , pattern MH_MAGIC32
  , pattern MH_MAGIC64
  , pattern MH_CIGAM32
  , pattern MH_CIGAM64
  , _getWord32
    -- ** Other header types
  , CPU_TYPE(..)
  , mach_to_cputype
  , CPU_SUBTYPE(..)
  , mach_to_cpusubtype
  , MH_FILETYPE(..)
    -- * Segments
  , MachoSegment(..)
  , SegmentName
  , getSegmentName
    -- ** Virtual memort protections
  , VM_PROT(..)
  , pattern VM_PROT_READ
  , pattern VM_PROT_WRITE
  , pattern VM_PROT_EXECUTE
    -- * Sections
  , MachoSection
  , SectionName
  , getSectionName
    -- * Symbols
  , MachoSymbol(..)
  , N_TYPE(..)
  , n_type
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
  , SG_FLAG
  , MH_FLAGS(..)
  , LC_COMMAND(..)
  , DylibModule(..)
  , MachoDynamicSymbolTable(..)
  , MachoSection(..)

  , SG_FLAG(..)
  , S_TYPE(..)
  , sectionType
  , S_SYS_ATTR(..)
  , S_USER_ATTR(..)
  -- * Decoder
  , Decoder
  , runDecoder
  , binary
  , decode
  , is64bit
  , getWord
  , getWord16
  , getWord32
  , getWord64
  , bitfield
  , lift
  ) where

import           Control.Applicative
import           Control.Monad
import           Data.Bimap (Bimap)
import qualified Data.Bimap as Bimap
import           Data.Binary.Get hiding (Decoder)
import           Data.Binary.Put
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Lazy as L
import           Data.Int
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Monoid
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

-- | Create magic from Word32
mkMagic :: Word32 -> Maybe MH_MAGIC
mkMagic w
  | Map.member (MH_MAGIC w) knownMagic = Just (MH_MAGIC w)
  | otherwise = Nothing



instance Show MH_MAGIC where
  show m =
    case Map.lookup m knownMagic of
      Just nm -> nm
      Nothing -> "0x" ++ showHex (magicValue m) ""

bitfield_le off sz word = (word `shiftL` (32 - off - sz)) `shiftR` (32 - sz)
bitfield_be off sz word = (word `shiftL` off) `shiftR` (32 - sz)

newtype Decoder a = Decoder { runDecoder :: MH_MAGIC -> Get a }

binary :: Decoder MH_MAGIC
binary = Decoder pure

decode :: B.ByteString -> Word32 -> Decoder a -> Decoder a
decode bs off ds = do
  b <- binary
  case runGetOrFail (runDecoder ds b) (L.fromChunks [B.drop (fromIntegral off) bs]) of
    Right (_,_,r) ->
      pure r
    Left (_,pos,msg) ->
      fail $ "Error decoding at position " ++ show pos ++ ": " ++ msg

getWord :: Decoder Word64
getWord = do
  is64 <- is64bit
  if is64 then getWord64 else fromIntegral <$> getWord32

lift :: Get a -> Decoder a
lift g = Decoder (\_ -> g)

instance Functor Decoder where
  fmap = liftM

instance Applicative Decoder where
  pure = return
  (<*>) = ap

instance Monad Decoder where
  return x = Decoder (\_ -> return x)
  Decoder f >>= g = Decoder $ \h -> do x <- f h;  runDecoder (g x) h
  fail msg = Decoder $ \_ -> fail msg

is64bit :: Decoder Bool
is64bit = Decoder (pure . magicIs64Bit)

getWord16 :: Decoder Word16
getWord16 = Decoder _getWord16

getWord32 :: Decoder Word32
getWord32 = Decoder _getWord32

getWord64 :: Decoder Word64
getWord64 = Decoder _getWord64

bitfield  :: Int -> Int -> Word32 -> Decoder Word32
bitfield i j x = Decoder (\h -> pure $ _bitfield h i j x)

{-
type MachoBinary = MH_MAGIC

_is64bit :: MachoBinary -> Bool
_is64bit = magicIs64Bit
-}

_getWord16 :: MH_MAGIC -> Get Word16
_getWord16 m = if magicIsLittleEndian m then getWord16le else getWord16be

_getWord32 :: MH_MAGIC -> Get Word32
_getWord32 m = if magicIsLittleEndian m then getWord32le else getWord32be

_getWord64 :: MH_MAGIC -> Get Word64
_getWord64 m = if magicIsLittleEndian m then getWord64le else getWord64be

_putWord16 :: MH_MAGIC -> Word16 -> Put
_putWord16 m = if magicIsLittleEndian m then putWord16le else putWord16be

_putWord32 :: MH_MAGIC -> Word32 -> Put
_putWord32 m = if magicIsLittleEndian m then putWord32le else putWord32be

_putWord64 :: MH_MAGIC -> Word64 -> Put
_putWord64 m = if magicIsLittleEndian m then putWord64le else putWord64be

_bitfield  :: MH_MAGIC -> Int -> Int -> Word32 -> Word32
_bitfield m = if magicIsLittleEndian m then bitfield_le else bitfield_be


data CPU_TYPE
    = CPU_TYPE_X86
    | CPU_TYPE_X86_64
    | CPU_TYPE_ARM
    | CPU_TYPE_POWERPC
    | CPU_TYPE_POWERPC64
    deriving (Ord, Show, Eq, Enum)

cputype :: Bimap Word32 CPU_TYPE
cputype = Bimap.fromList
 [ (0x00000007, CPU_TYPE_X86)
 , (0x01000007, CPU_TYPE_X86_64)
 , (0x0000000c, CPU_TYPE_ARM)
 , (0x00000012, CPU_TYPE_POWERPC)
 , (0x01000012, CPU_TYPE_POWERPC64)
 ]

mach_to_cpusubtype :: CPU_TYPE -> Word32 -> CPU_SUBTYPE
mach_to_cputype = (cputype Bimap.!)

mach_from_cputype = (cputype Bimap.!>)

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

mach_to_cpusubtype = curry (cpusubtype Bimap.!)
mach_from_cpusubtype = (cpusubtype Bimap.!>)

data MachoHeader = MachoHeader
    { mh_magic :: !MH_MAGIC
    , mh_cputype    :: CPU_TYPE    -- ^ CPU family the Mach-O executes on.
    , mh_cpusubtype :: CPU_SUBTYPE -- ^ Specific CPU type the Mach-O executes on.
    , mh_filetype   :: !MH_FILETYPE -- ^ Type of Mach-o file.
    , mh_flags      :: [MH_FLAGS]  -- ^ Flags.
    } deriving (Show, Eq)

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

data MH_FLAGS
    = MH_NOUNDEFS                -- ^ the object file has no undefined references
    | MH_INCRLINK                -- ^ the object file is the output of an incremental link against a base file and can't be link edited again
    | MH_DYLDLINK                -- ^ the object file is input for the dynamic linker and can't be staticly link edited again
    | MH_BINDATLOAD              -- ^ the object file's undefined references are bound by the dynamic linker when loaded.
    | MH_PREBOUND                -- ^ the file has its dynamic undefined references prebound.
    | MH_SPLIT_SEGS              -- ^ the file has its read-only and read-write segments split
    | MH_LAZY_INIT
    | MH_TWOLEVEL                -- ^ the image is using two-level name space bindings
    | MH_FORCE_FLAT              -- ^ the executable is forcing all images to use flat name space bindings
    | MH_NOMULTIDEFS             -- ^ this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used.
    | MH_NOFIXPREBINDING         -- ^ do not have dyld notify the prebinding agent about this executable
    | MH_PREBINDABLE             -- ^ the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set.
    | MH_ALLMODSBOUND            -- ^ indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.
    | MH_SUBSECTIONS_VIA_SYMBOLS -- ^ safe to divide up the sections into sub-sections via symbols for dead code stripping
    | MH_CANONICAL               -- ^ the binary has been canonicalized via the unprebind operation
    | MH_WEAK_DEFINES            -- ^ the final linked image contains external weak symbols
    | MH_BINDS_TO_WEAK           -- ^ the final linked image uses weak symbols
    | MH_ALLOW_STACK_EXECUTION   -- ^ When this bit is set, all stacks  in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes.
    | MH_DEAD_STRIPPABLE_DYLIB
    | MH_ROOT_SAFE               -- ^ When this bit is set, the binary  declares it is safe for use in processes with uid zero
    | MH_SETUID_SAFE             -- ^ When this bit is set, the binary  declares it is safe for use in processes when issetugid() is true
    | MH_NO_REEXPORTED_DYLIBS    -- ^ When this bit is set on a dylib,  the static linker does not need to examine dependent dylibs to see if any are re-exported
    | MH_PIE                     -- ^ When this bit is set, the OS will load the main executable at a random address.  Only used in MH_EXECUTE filetypes.
    deriving (Ord, Show, Eq, Enum)

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
    | LC_ENCRYPTION_INFO Word32 B.ByteString
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
-- MachoSection

data MachoSection = MachoSection
    { sec_sectname    :: !SectionName
      -- ^ name of section
    , sec_segname     :: !SegmentName        -- ^ name of segment that should own this section
    , sec_addr        :: Word64        -- ^ virtual memoy address for section
    , sec_size        :: Word64        -- ^ size of section
    , sec_align       :: Int           -- ^ alignment required by section (literal form, not power of two, e.g. 8 not 3)
    , sec_relocs      :: [Relocation]  -- ^ relocations for this section
    , sec_type        :: S_TYPE        -- ^ type of section
    , sec_user_attrs  :: [S_USER_ATTR] -- ^ user attributes of section
    , sec_sys_attrs   :: [S_SYS_ATTR]  -- ^ system attibutes of section
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- MachoSegment

data MachoSegment = MachoSegment
    { seg_segname  :: !SegmentName         -- ^ segment name
    , seg_vmaddr   :: Word64         -- ^ virtual address where the segment is loaded
    , seg_vmsize   :: Word64         -- ^ size of segment at runtime
    , seg_fileoff  :: Word64         -- ^ file offset of the segment
    , seg_filesize :: Word64         -- ^ size of segment in file
    , seg_maxprot  :: VM_PROT        -- ^ maximum virtual memory protection
    , seg_initprot :: VM_PROT        -- ^ initial virtual memory protection
    , seg_flags    :: [SG_FLAG]      -- ^ segment flags
    , seg_sections :: [MachoSection] -- ^ sections owned by this segment
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- Macho

data Macho = Macho
    { m_header   :: MachoHeader  -- ^ Header information.
    , m_commands :: [LC_COMMAND] -- ^ List of load commands describing Mach-O contents.
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- Other

data SG_FLAG
    = SG_HIGHVM  -- ^ The file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files).
    | SG_NORELOC -- ^ This segment has nothing that was relocated in it and nothing relocated to it, that is it may be safely replaced without relocation.
    deriving (Show, Eq)

data S_TYPE
    = S_REGULAR                    -- ^ regular section
    | S_ZEROFILL                   -- ^ zero fill on demand section
    | S_CSTRING_LITERALS           -- ^ section with only literal C strings
    | S_4BYTE_LITERALS             -- ^ section with only 4 byte literals
    | S_8BYTE_LITERALS             -- ^ section with only 8 byte literals
    | S_LITERAL_POINTERS           -- ^ section with only pointers to literals
    | S_NON_LAZY_SYMBOL_POINTERS   -- ^ section with only non-lazy symbol pointers
    | S_LAZY_SYMBOL_POINTERS       -- ^ section with only lazy symbol pointers
    | S_SYMBOL_STUBS               -- ^ section with only symbol stubs, bte size of stub in the reserved2 field
    | S_MOD_INIT_FUNC_POINTERS     -- ^ section with only function pointers for initialization
    | S_MOD_TERM_FUNC_POINTERS     -- ^ section with only function pointers for termination
    | S_COALESCED                  -- ^ section contains symbols that are to be coalesced
    | S_GB_ZEROFILL                -- ^ zero fill on demand section (that can be larger than 4 gigabytes)
    | S_INTERPOSING                -- ^ section with only pairs of function pointers for interposing
    | S_16BYTE_LITERALS            -- ^ section with only 16 byte literals
    | S_DTRACE_DOF                 -- ^ section contains DTrace Object Format
    | S_LAZY_DYLIB_SYMBOL_POINTERS -- ^ section with only lazy symbol pointers to lazy loaded dylibs
    deriving (Show, Eq)

sectionType :: Word32 -> S_TYPE
sectionType flags = case flags .&. 0x000000ff of
    0x00 -> S_REGULAR
    0x01 -> S_ZEROFILL
    0x02 -> S_CSTRING_LITERALS
    0x03 -> S_4BYTE_LITERALS
    0x04 -> S_8BYTE_LITERALS
    0x05 -> S_LITERAL_POINTERS
    0x06 -> S_NON_LAZY_SYMBOL_POINTERS
    0x07 -> S_LAZY_SYMBOL_POINTERS
    0x08 -> S_SYMBOL_STUBS
    0x09 -> S_MOD_INIT_FUNC_POINTERS
    0x0a -> S_MOD_TERM_FUNC_POINTERS
    0x0b -> S_COALESCED
    0x0c -> S_GB_ZEROFILL
    0x0d -> S_INTERPOSING
    0x0e -> S_16BYTE_LITERALS
    0x0f -> S_DTRACE_DOF
    0x10 -> S_LAZY_DYLIB_SYMBOL_POINTERS

data S_USER_ATTR
    = S_ATTR_PURE_INSTRUCTIONS   -- ^ section contains only true machine instructions
    | S_ATTR_NO_TOC              -- ^ setion contains coalesced symbols that are not to be in a ranlib table of contents
    | S_ATTR_STRIP_STATIC_SYMS   -- ^ ok to strip static symbols in this section in files with the MH_DYLDLINK flag
    | S_ATTR_NO_DEAD_STRIP       -- ^ no dead stripping
    | S_ATTR_LIVE_SUPPORT        -- ^ blocks are live if they reference live blocks
    | S_ATTR_SELF_MODIFYING_CODE -- ^ used with i386 code stubs written on by dyld
    | S_ATTR_DEBUG               -- ^ a debug section
    deriving (Show, Eq)

data S_SYS_ATTR
    = S_ATTR_SOME_INSTRUCTIONS -- ^ section contains soem machine instructions
    | S_ATTR_EXT_RELOC         -- ^ section has external relocation entries
    | S_ATTR_LOC_RELOC         -- ^ section has local relocation entries
    deriving (Show, Eq)

------------------------------------------------------------------------
-- N_TYPE

data N_TYPE
    = N_UNDF       -- ^ undefined symbol, n_sect is 0
    | N_ABS        -- ^ absolute symbol, does not need relocation, n_sect is 0
    | N_SECT       -- ^ symbol is defined in section n_sect
    | N_PBUD       -- ^ symbol is undefined and the image is using a prebound value for the symbol, n_sect is 0
    | N_INDR       -- ^ symbol is defined to be the same as another symbol. n_value is a string table offset indicating the name of that symbol
    | N_GSYM       -- ^ stab global symbol: name,,0,type,0
    | N_FNAME      -- ^ stab procedure name (f77 kludge): name,,0,0,0
    | N_FUN        -- ^ stab procedure: name,,n_sect,linenumber,address
    | N_STSYM      -- ^ stab static symbol: name,,n_sect,type,address
    | N_LCSYM      -- ^ stab .lcomm symbol: name,,n_sect,type,address
    | N_BNSYM      -- ^ stab begin nsect sym: 0,,n_sect,0,address
    | N_OPT        -- ^ stab emitted with gcc2_compiled and in gcc source
    | N_RSYM       -- ^ stab register sym: name,,0,type,register
    | N_SLINE      -- ^ stab src line: 0,,n_sect,linenumber,address
    | N_ENSYM      -- ^ stab end nsect sym: 0,,n_sect,0,address
    | N_SSYM       -- ^ stab structure elt: name,,0,type,struct_offset
    | N_SO         -- ^ stab source file name: name,,n_sect,0,address
    | N_OSO        -- ^ stab object file name: name,,0,0,st_mtime
    | N_LSYM       -- ^ stab local sym: name,,0,type,offset
    | N_BINCL      -- ^ stab include file beginning: name,,0,0,sum
    | N_SOL        -- ^ stab #included file name: name,,n_sect,0,address
    | N_PARAMS     -- ^ stab compiler parameters: name,,0,0,0
    | N_VERSION    -- ^ stab compiler version: name,,0,0,0
    | N_OLEVEL     -- ^ stab compiler -O level: name,,0,0,0
    | N_PSYM       -- ^ stab parameter: name,,0,type,offset
    | N_EINCL      -- ^ stab include file end: name,,0,0,0
    | N_ENTRY      -- ^ stab alternate entry: name,,n_sect,linenumber,address
    | N_LBRAC      -- ^ stab left bracket: 0,,0,nesting level,address
    | N_EXCL       -- ^ stab deleted include file: name,,0,0,sum
    | N_RBRAC      -- ^ stab right bracket: 0,,0,nesting level,address
    | N_BCOMM      -- ^ stab begin common: name,,0,0,0
    | N_ECOMM      -- ^ stab end common: name,,n_sect,0,0
    | N_ECOML      -- ^ stab end common (local name): 0,,n_sect,0,address
    | N_LENG       -- ^ stab second stab entry with length information
    | N_PC         -- ^ stab global pascal symbol: name,,0,subtype,line
    deriving (Show, Eq)

n_type :: Word8 -> N_TYPE
n_type 0x00 = N_UNDF
n_type 0x01 = N_ABS
n_type 0x07 = N_SECT
n_type 0x06 = N_PBUD
n_type 0x05 = N_INDR
n_type 0x20 = N_GSYM
n_type 0x22 = N_FNAME
n_type 0x24 = N_FUN
n_type 0x26 = N_STSYM
n_type 0x28 = N_LCSYM
n_type 0x2e = N_BNSYM
n_type 0x3c = N_OPT
n_type 0x40 = N_RSYM
n_type 0x44 = N_SLINE
n_type 0x4e = N_ENSYM
n_type 0x60 = N_SSYM
n_type 0x64 = N_SO
n_type 0x66 = N_OSO
n_type 0x80 = N_LSYM
n_type 0x82 = N_BINCL
n_type 0x84 = N_SOL
n_type 0x86 = N_PARAMS
n_type 0x88 = N_VERSION
n_type 0x8A = N_OLEVEL
n_type 0xa0 = N_PSYM
n_type 0xa2 = N_EINCL
n_type 0xa4 = N_ENTRY
n_type 0xc0 = N_LBRAC
n_type 0xc2 = N_EXCL
n_type 0xe0 = N_RBRAC
n_type 0xe2 = N_BCOMM
n_type 0xe4 = N_ECOMM
n_type 0xe8 = N_ECOML
n_type 0xfe = N_LENG
n_type 0x30 = N_PC

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

referenceType :: REFERENCE_FLAG -> REFERENCE_TYPE
referenceType (REFERENCE_FLAG w) = REFERENCE_TYPE (fromIntegral (w .&. 0xf))

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
    { sym_name  :: String                         -- ^ symbol name
    , sym_type  :: N_TYPE                         -- ^ symbol type
    , sym_pext  :: Bool                           -- ^ true if limited global scope
    , sym_ext   :: Bool                           -- ^ true if external symbol
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
