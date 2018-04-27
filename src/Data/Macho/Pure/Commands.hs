{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.Macho.Pure.Commands
  ( -- * Commands
    LC_COMMAND(..)
  , ppLoadCommands
  , parseCommands
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
  , DyldInfoCommand(..)
  , VersionMinCommand(..)
  , EntryPointCommand(..)
  , SourceVersionCommand(..)
  , RoutinesCommand(..)
  , Timestamp(..)
  , Version(..)
    -- * Segments
  , MachoSegment(..)
  , Addr(..)
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
  , module Data.Macho.Pure.Commands.Section
  , Align(..)
    -- * Dynamic symbol table
  , DysymtabCommand(..)
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
  ) where

import           Data.Macho.Pure.Commands.Dysymtab
import           Data.Macho.Pure.Commands.Section
import           Data.Macho.Pure.Decoder
import           Data.Macho.Pure.Header (MH_MAGIC)
import           Data.Macho.Pure.Internal

import           Control.Monad
import           Data.Binary.Get hiding (Decoder)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.UTF8 as UTF8
import           Data.Map (Map)
import qualified Data.Map.Strict as Map
import           Data.Monoid
-- Import UTCTime show instance from Format
import           Data.Time.Format ()
import           Data.Time.Clock.POSIX
import qualified Data.Vector as V
import           Data.Word
import           Numeric (showHex)

newtype Attrs = Attrs [(String, String)]

instance Monoid Attrs where
  mempty = Attrs []
  mappend (Attrs x) (Attrs y) = Attrs (x ++ y)

instance Show Attrs where
  show = ppAttrs

mkAttr :: String -> String -> String
mkAttr nm v = nm ++  " " ++ v ++ "\n"

-- | Print a list of name value pairs with one on each line.
ppAttrs :: Attrs -> String
ppAttrs (Attrs []) = ""
ppAttrs (Attrs l) =
  let lenList = (length . fst <$> l)
      n = 1 + maximum lenList
      pp i (nm,v) = replicate (n - i) ' ' ++ nm ++ " " ++ v ++ "\n"
   in concat (zipWith pp lenList l)

class PPFields tp where
  ppFields :: String -> tp -> String

------------------------------------------------------------------------
-- Addr

newtype Addr = Addr Word64
  deriving (Eq)

instance Show Addr where
  show (Addr a) = showPadHex a

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

instance CommandType FileOffset where
  getValue _ = FileOffset <$> getWord32

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
-- MachoSection

ppSection :: (FiniteBits w, Integral w, Show w) => MachoSection w -> String
ppSection s
  = "Section\n"
  <> mkAttr "  sectname" (show (secSectname s))
  <> mkAttr "   segname" (show (secSegname s))
  <> mkAttr "      addr" (showPadHex (secAddr s))
  <> mkAttr "      size" (showPadHex (secSize s))
  <> mkAttr "    offset" (show (secAlign s))
  <> mkAttr "    reloff" (show (secReloff s))
  <> mkAttr "    nreloc" (show (secNReloc s))
  <> mkAttr "     flags" (show (secFlags s))
  <> mkAttr " reserved1" (show (secReserved1 s))
  <> mkAttr " reserved2" (show (secReserved2 s))

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
  show (VM_PROT v) = showPadHex v

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

instance PPFields SymTabCommand where
  ppFields cmd x
    =  mkAttr "     cmd" cmd
    <> mkAttr "  symoff" (show (symTabOffset x))
    <> mkAttr "   nsyms" (show (symTabSymCount x))
    <> mkAttr "  stroff" (show (symTabStrOffset x))
    <> mkAttr " strsize" (show (symTabStrSize x))

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
newtype LCStr = LCStr { lcStrData :: B.ByteString }
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
      fail $ "Thread command count is too large " ++ show count
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

instance CommandType DysymtabCommand where
  getValue = getRecord DysymtabCommand

instance PPFields DysymtabCommand where
  ppFields cmd d
    =  mkAttr "            cmd" cmd
    <> mkAttr "      ilocalsym" (show (dysymtabILocalSym d))
    <> mkAttr "      nlocalsym" (show (dysymtabNLocalSym d))
    <> mkAttr "     iextdefsym" (show (dysymtabIExtdefSym d))
    <> mkAttr "     nextdefsym" (show (dysymtabNExtdefSym d))
    <> mkAttr "      iundefsym" (show (dysymtabIUndefSym d))
    <> mkAttr "      nundefsym" (show (dysymtabNUndefSym d))
    <> mkAttr "         tocoff" (show (dysymtabTocOff d))
    <> mkAttr "           ntoc" (show (dysymtabTocCount d))
    <> mkAttr "      modtaboff" (show (dysymtabModtabOff d))
    <> mkAttr "        nmodtab" (show (dysymtabModtabCount d))
    <> mkAttr "   extrefsymoff" (show (dysymtabExtrefSymOff d))
    <> mkAttr "    nextrefsyms" (show (dysymtabExtrefSymCount d))
    <> mkAttr " indirectsymoff" (show (dysymtabIndirectSymOff d))
    <> mkAttr "  nindirectsyms" (show (dysymtabIndirectSymCount d))
    <> mkAttr "      extreloff" (show (dysymtabExtRelOff d))
    <> mkAttr "        nextrel" (show (dysymtabExtRelCount d))
    <> mkAttr "      locreloff" (show (dysymtabLocalRelOff d))
    <> mkAttr "        nlocrel" (show (dysymtabLocalRelCount d))


------------------------------------------------------------------------
-- Timestamp

-- | A timestamp in Macho uses the posix convention of representing
-- time as the number of seconds since 1970-01-01 00:00 UTC
newtype Timestamp = Timestamp Word32
  deriving (Eq)

-- Print using UTC time
instance Show Timestamp where
  show (Timestamp x) = show (posixSecondsToUTCTime (fromIntegral x))

instance CommandType Timestamp where
  getValue _ = Timestamp <$> getWord32

------------------------------------------------------------------------
-- DylibCommand

data DylibCommand = DylibCommand { symlibNameOffset :: !LCStr
                                 , symlibTimestamp :: !Timestamp
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

data RoutinesCommand w
  = RoutinesCommand
  { routinesInitAddress :: !w
  , routinesInitModule  :: !w
  , routinesReserved    :: !(V.Vector w)
    -- ^ A list of 6 reserved words
  }
  deriving (Eq, Show)

instance CommandType w => CommandType (RoutinesCommand w) where
  getValue lc = do
    init_address <- getValue lc
    init_module  <- getValue lc
    res <- V.replicateM 6 (getValue lc)
    pure $ RoutinesCommand { routinesInitAddress = init_address
                           , routinesInitModule  = init_module
                           , routinesReserved    = res
                           }

instance (FiniteBits w, Integral w, Show w) => PPFields (RoutinesCommand w) where
  ppFields cmd x
    =  mkAttr      "          cmd" cmd
    <> mkAttr      " init_address" (showPadHex (routinesInitAddress x))
    <> mkAttr      "  init_module" (show (routinesInitModule x))
    <> mconcat (zipWith ppR  [1..] (V.toList (routinesReserved x)))
   where ppR :: Int -> w -> String
         ppR i r = mkAttr ("    reserved" ++ show i) (show r)

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
            | otherwise = toEnum (fromEnum 'A' + fromIntegral (w-10)) : s

instance CommandType UUID where
  getValue _ = lift $ UUID <$> getByteString 16

instance PPFields UUID where
  ppFields cmd x
    =  mkAttr "     cmd" cmd
    <> mkAttr "    uuid" (show x)

------------------------------------------------------------------------
-- EncryptionInfoCommand

data EncryptionInfoCommand
  = EncryptionInfoCommand
  { cryptOff :: !Word32
  , cryptSize :: !Word32
  , cryptId   :: !Word32
  }
  deriving (Eq, Show)

-- | Decode an encryption info command with a given amount of padding.
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

instance PPFields DyldInfoCommand where
  ppFields cmd d
    =  mkAttr "            cmd" cmd
    <> mkAttr "     rebase_off" (show (rebaseOff d))
    <> mkAttr "    rebase_size" (show (rebaseSize d))
    <> mkAttr "       bind_off" (show (bindOff d))
    <> mkAttr "      bind_size" (show (bindSize d))
    <> mkAttr "  weak_bind_off" (show (weakBindOff d))
    <> mkAttr " weak_bind_size" (show (weakBindSize d))
    <> mkAttr "  lazy_bind_off" (show (lazyBindOff d))
    <> mkAttr " lazy_bind_size" (show (lazyBindSize d))
    <> mkAttr "     export_off" (show (exportOff d))
    <> mkAttr "    export_size" (show (exportSize d))

------------------------------------------------------------------------
-- Version

-- | A verission is a 32-bit word that encodes a major version and option
-- minor and trivial versions.
newtype Version = Version Word32
  deriving (Eq)

instance CommandType Version where
  getValue _ = Version <$> getWord32

instance Show Version where
  show (Version w)
      | v2 /= 0   = show v0 ++ "." ++ show v1 ++ "." ++ show v2
      | v1 /= 0   = show v0 ++ "." ++ show v1
      | otherwise = show v0
    where v0 = w `shiftR` 16
          v1 = (w `shiftR` 8) .&. 0xff
          v2 = w .&. 0xff

------------------------------------------------------------------------
-- SourceVersion

newtype SourceVersionCommand = SourceVersionCommand { sourceVersionValue :: Word64 }
  deriving (Eq)

instance CommandType SourceVersionCommand where
  getValue _ = SourceVersionCommand <$> getWord64

instance Show SourceVersionCommand where
  show (SourceVersionCommand x)
      | e /= 0  = ae
      | d /= 0  = ad
      | c /= 0  = ac
      | otherwise = ab
    where a = x `shiftR` 40
          b = (x `shiftR` 30) .&. 0x3ff
          c = (x `shiftR` 20) .&. 0x3ff
          d = (x `shiftR` 10) .&. 0x3ff
          e = x  .&. 0x3ff
          app s v = s ++ "." ++ show v

          ab = app (show a) b
          ac = app ab c
          ad = app ac d
          ae = app ad e

instance PPFields SourceVersionCommand where
  ppFields cmd x
    =  mkAttr "      cmd" cmd
    <> mkAttr "  version" (show x)

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
    | LC_SOURCE_VERSION !SourceVersionCommand
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

instance (Integral w, Show w, FiniteBits w) => PPFields (MachoSegment w) where

  ppFields cmd s
    =  mkAttr "      cmd" cmd
    <> mkAttr "  segname" (show (seg_segname s))
    <> mkAttr "   vmaddr" (showPadHex (seg_vmaddr s))
    <> mkAttr "   vmsize" (showPadHex (seg_vmsize s))
    <> mkAttr "  fileoff" (show (seg_fileoff s))
    <> mkAttr " filesize" (show (seg_filesize s))
    <> mkAttr "  maxprot" (show (seg_maxprot s))
    <> mkAttr " initprot" (show (seg_initprot s))
    <> mkAttr "   nsects" (show (length (seg_sections s)))
    <> mkAttr "    flags" (show (seg_flags s))
    <> mconcat (ppSection <$> seg_sections s)

-- | Pretty print load commands in a style similiar to otool.
ppLoadCommand :: LC_COMMAND -> String
ppLoadCommand (LC_SEGMENT s)        = ppFields "LC_SEGMENT" s
ppLoadCommand (LC_SYMTAB x)         = ppFields "LC_SYMTAB" x

ppLoadCommand (LC_DYSYMTAB s)       = ppFields "LC_DYSYMTAB" s

ppLoadCommand (LC_LOAD_DYLINKER x)
  =  mkAttr "          cmd" "LC_LOAD_DYLINKER"
  <> mkAttr "         name" (show x)
ppLoadCommand (LC_ID_DYLINKER x)
  =  mkAttr "          cmd" "LC_ID_DYLINKER"
  <> mkAttr "         name" (show x)

ppLoadCommand (LC_ROUTINES x) = ppFields "LC_ROUTINES" x

ppLoadCommand (LC_SEGMENT_64 x)  = ppFields  "LC_SEGMENT_64" x
ppLoadCommand (LC_ROUTINES_64 x) = ppFields "LC_ROUTINES_64" x
ppLoadCommand (LC_UUID x) = ppFields "LC_UUID" x
ppLoadCommand (LC_RPATH x)
  =  mkAttr "          cmd" "LC_RPATH"
  <> mkAttr "         path" (show x)

ppLoadCommand (LC_DYLD_INFO d)      = ppFields "LC_DYLD_INFO" d
ppLoadCommand (LC_DYLD_INFO_ONLY d) = ppFields "LC_DYLD_INFO_ONLY" d

ppLoadCommand (LC_SOURCE_VERSION x) = ppFields "LC_SOURCE_VERSION" x

ppLoadCommand c = mkAttr "UNKNOWN" (show c)

-- | Pretty print the list of commands using otool format.
ppLoadCommands :: [LC_COMMAND] -> String
ppLoadCommands cmds = concat (zipWith pp [0..] cmds)
  where pp :: Integer -> LC_COMMAND -> String
        pp i c = "Load command " ++ show i ++ "\n" ++ ppLoadCommand c

------------------------------------------------------------------------
-- Load commands

-- | A command getter starts with the command contents, but also has it passed in as a bytestring.
type CommandGetter =
      B.ByteString
       -> Decoder LC_COMMAND

-- | Map from command type code to the parser for that command.
loadCommandMap :: Map Word32 CommandGetter
loadCommandMap = Map.fromList
  [ (,) 0x00000001 $ fmap LC_SEGMENT    . getValue
  , (,) 0x00000002 $ fmap LC_SYMTAB     . getValue
  , (,) 0x00000003 $ fmap LC_SYMSEG     . getValue
  , (,) 0x00000004 $ fmap LC_THREAD     . getValue
  , (,) 0x00000005 $ fmap LC_UNIXTHREAD . getValue
  , (,) 0x00000006 $ fmap LC_LOADFVMLIB . getValue
  , (,) 0x00000007 $ fmap LC_IDFVMLIB   . getValue
  , (,) 0x00000008 $ pure . LC_IDENT
  , (,) 0x00000009 $ fmap LC_FVMFILE . getValue
  , (,) 0x0000000a $ pure . LC_PREPAGE
  , (,) 0x0000000b $ fmap LC_DYSYMTAB . getValue
  , (,) 0x0000000c $ fmap LC_LOAD_DYLIB     . getValue
  , (,) 0x0000000d $ fmap LC_ID_DYLIB       . getValue
  , (,) 0x0000000e $ fmap LC_LOAD_DYLINKER  . getValue
  , (,) 0x0000000f $ fmap LC_ID_DYLINKER    . getValue
  , (,) 0x00000010 $ fmap LC_PREBOUND_DYLIB . getValue
  , (,) 0x00000011 $ fmap LC_ROUTINES . getValue
  , (,) 0x00000012 $ fmap LC_SUB_FRAMEWORK . getValue
  , (,) 0x00000013 $ fmap LC_SUB_UMBRELLA  . getValue
  , (,) 0x00000014 $ fmap LC_SUB_CLIENT    . getValue
  , (,) 0x00000015 $ fmap LC_SUB_LIBRARY   . getValue
  , (,) 0x00000016 $ \_  -> LC_TWOLEVEL_HINTS <$> (FileOffset <$> getWord32) <*> getWord32
  , (,) 0x00000017 $ fmap LC_PREBIND_CKSUM . getValue
  , (,) 0x80000018 $ fmap LC_LOAD_WEAK_DYLIB . getValue
  , (,) 0x00000019 $ fmap LC_SEGMENT_64  . getValue
  , (,) 0x0000001a $ fmap LC_ROUTINES_64 . getValue
  , (,) 0x0000001b $ fmap LC_UUID  . getValue
  , (,) 0x8000001c $ fmap LC_RPATH . getValue
  , (,) 0x0000001d $ fmap LC_CODE_SIGNATURE . getValue
  , (,) 0x0000001e $ fmap LC_SEGMENT_SPLIT_INFO . getValue
  , (,) 0x8000001f $ fmap LC_REEXPORT_DYLIB . getValue
  , (,) 0x00000020 $ fmap LC_LAZY_LOAD_DYLIB . getValue
  , (,) 0x00000021 $ \_  -> LC_ENCRYPTION_INFO <$> getEncryptionInfoCommand 0
  , (,) 0x00000022 $ fmap LC_DYLD_INFO      . getValue
  , (,) 0x80000022 $ fmap LC_DYLD_INFO_ONLY . getValue
  , (,) 0x80000023 $ fmap LC_LOAD_UPWARD_DYLIB . getValue
  , (,) 0x00000024 $ fmap LC_VERSION_MIN_MACOSX   . getValue
  , (,) 0x00000025 $ fmap LC_VERSION_MIN_IPHONEOS . getValue
  , (,) 0x00000026 $ fmap LC_FUNCTION_STARTS . getValue
  , (,) 0x00000027 $ fmap LC_DYLD_ENVIRONMENT . getValue
  , (,) 0x80000028 $ fmap LC_MAIN . getValue
  , (,) 0x00000029 $ fmap LC_DATA_IN_CODE . getValue
  , (,) 0x0000002a $ fmap LC_SOURCE_VERSION . getValue
  , (,) 0x0000002b $ fmap LC_DYLIB_CODE_SIGN_DRS . getValue
  , (,) 0x0000002c $ \_  -> LC_ENCRYPTION_INFO_64 <$> getEncryptionInfoCommand 4
  , (,) 0x0000002d $ fmap LC_LINKER_OPTION . getValue
  , (,) 0x0000002e $ fmap LC_LINKER_OPTIMIZATION_HINT . getValue
  , (,) 0x0000002f $ fmap LC_VERSION_MIN_TVOS . getValue
  , (,) 0x00000030 $ fmap LC_VERSION_MIN_WATCHOS . getValue
  , (,) 0x00000031 $ pure . LC_NOTE
  , (,) 0x00000032 $ fmap LC_BUILD_VERSION . getValue
  ]

getLoadCommand :: Decoder LC_COMMAND
getLoadCommand = do
  magic <- binary
  let end = magicEndianness magic

  -- Peek to find code and cmd
  (code,cmdsize) <- lift $
    lookAhead $ (,) <$> (_getWord32 end) <*> (_getWord32 end)
  when (cmdsize < 8) $ do
    fail "Invalid command size"
  -- Get full contents
  contents <- lift $ getByteString (fromIntegral cmdsize)
  pure $!
    case Map.lookup code loadCommandMap of
      Nothing ->
        LC_UNKNOWN code contents
      Just getter -> do
        case doDecode magic (B.drop 8 contents) (getter contents) of
          Right (_,_,r) -> r
          Left (_,pos,msg) -> LC_INVALID code contents pos msg

getLoadCommands :: Word32 -> Decoder [LC_COMMAND]
getLoadCommands ncmds = replicateM (fromIntegral ncmds) $ getLoadCommand

-- | Parse the buffer as a list of commands.
parseCommands :: MH_MAGIC
              -> Word32
              -> B.ByteString
              -> Either (ByteOffset, String) [LC_COMMAND]
parseCommands magic ncmds loadCommandBuffer =
  case doDecode magic loadCommandBuffer (getLoadCommands ncmds) of
    Left (_,pos,msg) -> Left (pos, msg)
    Right (_,_,commands) -> Right commands
