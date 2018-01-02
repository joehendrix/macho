-- | Data.Macho is a module for parsing a ByteString of a Mach-O file into a Macho record.
module Data.MachoPure
  ( Macho(..)
  , ppLoadCommands
  , parseMacho
  , MachoError(..)
  , module Data.MachoPure.Header
  , module Data.MachoPure.Commands
    -- * Additional parsers.
  , getSymTabEntries
  , getTwoLevelHints
  , getTocEntries
  , getModules
  , getExtRefSyms
  , getIndirectSyms
  , getExternalLocations
  , getLocalRelocations
  , getSectionRelocs
  ) where

import           Control.Monad
import           Data.Binary hiding (decode)
import           Data.Binary.Get hiding (Decoder)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Data.Map (Map)
import qualified Data.Map as Map
import           Numeric

import           Data.MachoPure.Commands
import           Data.MachoPure.Decoder
import           Data.MachoPure.Header
import           Data.MachoPure.Relocations
import           Data.MachoPure.Symbols

subbuffer :: B.ByteString -> FileOffset -> Word32 -> Maybe B.ByteString
subbuffer b (FileOffset o) c = do
  when (toInteger (B.length b) < toInteger o + toInteger c) $
    Nothing
  Just $ B.take (fromIntegral c) $ B.drop (fromIntegral o) b

getTable :: MH_MAGIC -> B.ByteString -> FileOffset -> Word32 -> Word32 -> Decoder a -> Maybe [a]
getTable magic contents off cnt sz dec = do
  when (cnt >= (maxBound :: Word32) `div` sz) $ Nothing
  buf <- subbuffer contents off (sz*cnt)
  case doDecode magic buf (replicateM (fromIntegral cnt) dec) of
    Left{} -> error $ "internal: getTable check failed."
    Right (_,_,v) -> Just v

-- | Number of bytes in a macho header
headerSize :: MH_MAGIC -> Int
headerSize magic = if magicIs64Bit magic then 32 else 28

getMachoHeader :: Get (MachoHeader, Word32, Word32)
getMachoHeader = do
  magicVal      <- getWord32le
  magic <-
    case mkMagic magicVal of
      Just magic -> pure magic
      Nothing -> fail $ "Unknown magic: 0x" ++ showHex magicVal "."
  cputype    <- CPU_TYPE <$> _getWord32 magic


  cpusubtype <- CPU_SUBTYPE <$> _getWord32 magic
  filetype   <- MH_FILETYPE <$> _getWord32 magic

  ncmds      <- _getWord32 magic
  sizeofcmds <- _getWord32 magic

  flags      <- MH_FLAGS <$> _getWord32 magic

  -- 64-bit mode has four byte padding.
  when (magicIs64Bit magic) $ do
    void $ getWord32le

  let hdr = MachoHeader { mh_magic = magic
                        , mh_cputype = cputype
                        , mh_cpusubtype = cpusubtype
                        , mh_filetype = filetype
                        , mh_flags = flags
                        }
  return (hdr, ncmds, sizeofcmds)

getTwoLevelHint :: Decoder (Word32, Word32)
getTwoLevelHint = do
  word <- getWord32
  isub_image <- bitfield 0 8 word
  itoc       <- bitfield 8 24 word
  return (isub_image, itoc)

-- | This returns the two level hints entry or Nothing if the buffer is not large enough.
getTwoLevelHints :: MH_MAGIC -> B.ByteString -> FileOffset -> Word32 -> Maybe [(Word32, Word32)]
getTwoLevelHints magic contents off cnt = getTable magic contents off cnt 4 getTwoLevelHint

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
    let info = RelocationInfo { ri_address = fromIntegral r_address
                              , ri_symbolnum = symbolnum
                              , ri_pcrel = pcrel == 1
                              , ri_length = 2 ^ len
                              , ri_extern = extern == 1
                              , ri_type = tp
                              }
    return $ Unscattered info

getSectionRelocs :: MH_MAGIC -> B.ByteString -> MachoSection w -> Maybe [Relocation]
getSectionRelocs m b s = getTable m b (secReloff s) (secNReloc s) relocationSize getRel

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
  typeCode  <- lift $ SymbolType <$> getWord8
  n_sect  <- lift $ getWord8
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

-- | Returns the symbol table entry size
symtabEntrySize :: MH_MAGIC -> Word32
symtabEntrySize magic = 8 + magicWordSize magic

-- | This attempts to parse the symbol table entries from the command info
getSymTabEntries :: MH_MAGIC -> B.ByteString -> SymTabCommand -> Maybe [MachoSymbol]
getSymTabEntries magic contents cmd = do
  strsect <- subbuffer contents (symTabStrOffset cmd) (symTabStrSize cmd)
  getTable magic contents (symTabOffset cmd) (symTabSymCount cmd)
           (symtabEntrySize magic) (getNList strsect)

getTOC :: Decoder (Word32, Word32)
getTOC = do
  symbol_index <- getWord32
  module_index <- getWord32
  return (symbol_index, module_index)

-- | Module size
dylibModuleSize :: MH_MAGIC -> Word32
dylibModuleSize magic = 12 * 4 + magicWordSize magic

getModule :: Decoder DylibModule
getModule = do
    module_name           <- getWord32
    iextdefsym            <- getWord32
    nextdefsym            <- getWord32
    irefsym               <- getWord32

    nrefsym               <- getWord32
    ilocalsym             <- getWord32
    nlocalsym             <- getWord32
    iextrel               <- getWord32

    nextrel               <- getWord32
    iinit_iterm           <- getWord32
    let iinit = (iinit_iterm .&. 0x0000ffff)
    let iterm = (iinit_iterm .&. 0xffff0000) `shiftR` 16
    ninit_nterm           <- getWord32
    let ninit = (ninit_nterm .&. 0x0000ffff)
    let nterm = (ninit_nterm .&. 0xffff0000) `shiftR` 16
    objc_module_info_addr <- getWord
    objc_module_info_size <- getWord32
    return $!
      DylibModule
      { dylib_module_name_offset    = module_name
      , dylib_ext_def_sym           = (iextdefsym, nextdefsym)
      , dylib_ref_sym               = (irefsym, nrefsym)
      , dylib_local_sym             = (ilocalsym, nlocalsym)
      , dylib_ext_rel               = (iextrel, nextrel)
      , dylib_init                  = (iinit, ninit)
      , dylib_term                  = (iterm, nterm)
      , dylib_objc_module_info_addr = objc_module_info_addr
      , dylib_objc_module_info_size = objc_module_info_size
      }

-- | Get table of content entries from file.
getTocEntries :: MH_MAGIC -> B.ByteString -> DysymtabCommand -> Maybe [(Word32, Word32)]
getTocEntries magic contents cmd
  = getTable magic contents (dysymtabTocOff cmd) (dysymtabTocCount cmd) 8 getTOC

-- | List of modules
getModules :: MH_MAGIC -> B.ByteString -> DysymtabCommand -> Maybe [DylibModule]
getModules magic contents cmd =
  getTable magic contents (dysymtabModtabOff cmd) (dysymtabModtabCount cmd)
           (dylibModuleSize magic) getModule

-- | List of external refernce symbol indices
getExtRefSyms :: MH_MAGIC -> B.ByteString -> DysymtabCommand -> Maybe [Word32]
getExtRefSyms magic contents cmd =
  getTable magic contents (dysymtabExtrefSymOff cmd) (dysymtabExtrefSymCount cmd) 4 getWord32

-- | List of external refernce symbol indices
getIndirectSyms :: MH_MAGIC -> B.ByteString -> DysymtabCommand -> Maybe [Word32]
getIndirectSyms magic contents cmd =
  getTable magic contents (dysymtabIndirectSymOff cmd) (dysymtabIndirectSymCount cmd) 4 getWord32

-- | List of external locations
getExternalLocations :: MH_MAGIC -> B.ByteString -> DysymtabCommand -> Maybe [Relocation]
getExternalLocations magic contents cmd =
  getTable magic contents (dysymtabExtRelOff cmd) (dysymtabExtRelCount cmd) relocationSize getRel

-- | List of local relocations.
getLocalRelocations :: MH_MAGIC -> B.ByteString -> DysymtabCommand -> Maybe [Relocation]
getLocalRelocations magic contents cmd =
  getTable magic contents (dysymtabLocalRelOff cmd) (dysymtabLocalRelCount cmd) relocationSize getRel

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
  -- Peek to find code and cmd
  (code,cmdsize) <- lift $
    lookAhead $ (,) <$> (_getWord32 magic) <*> (_getWord32 magic)
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

------------------------------------------------------------------------
-- parseMacho

data Macho = Macho
    { m_header   :: MachoHeader  -- ^ Header information.
    , m_commands :: [LC_COMMAND] -- ^ List of load commands describing Mach-O contents.
    } deriving (Show, Eq)

ppLoadCommands :: Macho -> String
ppLoadCommands m = concat (zipWith pp [0..] (m_commands m))
  where pp :: Integer -> LC_COMMAND -> String
        pp i c = "Load command " ++ show i ++ "\n" ++ ppLoadCommand c

data MachoError
   = HeaderError !ByteOffset !String
   | CommandError !ByteOffset !String

instance Show MachoError where
  show (HeaderError pos msg) = "Could not decode header at pos " ++ show pos ++ ": " ++ msg
  show (CommandError pos msg) = "Could not decode commands at pos " ++ show pos ++ ": " ++ msg

-- | Parse a ByteString of a Mach-O object into a Macho record.
parseMacho :: B.ByteString -> Either MachoError Macho
parseMacho b =
  case runGetOrFail getMachoHeader (L.fromChunks [b]) of
    Left (_,pos,msg) ->
      Left $ HeaderError pos msg
    Right (_,_, (header, ncmds, sizeofcmds)) -> do
      let magic = mh_magic header
      let loadCommandBuffer = B.take (fromIntegral sizeofcmds) $ B.drop (headerSize magic) b
      case doDecode magic loadCommandBuffer (getLoadCommands ncmds) of
        Left (_,pos,msg) -> do
          Left $ CommandError pos msg
        Right (_,_,commands) ->
          Right $ Macho header commands
