-- | Data.Macho is a module for parsing a ByteString of a Mach-O file into a Macho record.
module Data.MachoPure ( parseMacho
                      , Macho(..)
                      , MachoError(..)
                      , MachoHeader(..)
                      , LC_COMMAND(..)
                      , CPU_TYPE(..)
                      , CPU_SUBTYPE(..)
                      , MH_FLAGS(..)
                      , VM_PROT(..)
                      , MachoSegment(..)
                      , SG_FLAGS(..)
                      , MachoSection(..)
                      , S_TYPE(..)
                      , S_USER_ATTR(..)
                      , S_SYS_ATTR(..)
                      , N_TYPE(..)
                      , REFERENCE_FLAG(..)
                      , MachoSymbol(..)
                      , DylibModule(..)
                      , R_TYPE(..)
                      , Relocation(..)
                      , MachoDynamicSymbolTable(..)
                      , MH_FILETYPE(..)) where

import           Control.Monad
import           Data.Binary hiding (decode)
import           Data.Binary.Get hiding (Decoder)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Maybe
import           Numeric

import           Data.MachoPure.Types


-- | Number of bytes in a macho header
headerSize :: Int
headerSize = 32

getMachoHeader :: Get (MH_MAGIC, Word32, MachoHeader)
getMachoHeader = do
  magicVal      <- getWord32le
  magic <-
    case mkMagic magicVal of
      Just magic -> pure magic
      Nothing -> fail $ "Unknown magic: 0x" ++ showHex magicVal "."
  Just cputype    <- mach_to_cputype <$> _getWord32 magic

  cpusubtype <- mach_to_cpusubtype cputype <$> _getWord32 magic
  filetype   <- MH_FILETYPE <$> _getWord32 magic

  _ncmds      <- _getWord32 magic
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
  return (magic, sizeofcmds, hdr)


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
    Right (_,_,(mr, sizeofcmds, header)) ->
      case runGetOrFail (runDecoder (getLoadCommands b header) mr)
                        (L.fromChunks [B.take (fromIntegral sizeofcmds) $ B.drop headerSize b]) of
        Left (_,pos,msg) -> do
          Left $ CommandError pos msg
        Right (_,_,commands) ->
          Right $ Macho header commands



getTwoLevelHint :: Decoder (Word32, Word32)
getTwoLevelHint = do
  word <- getWord32
  isub_image <- bitfield 0 8 word
  itoc       <- bitfield 8 24 word
  return (isub_image, itoc)

getTwoLevelHintsCommand :: B.ByteString -> Decoder LC_COMMAND
getTwoLevelHintsCommand fl = do
  offset  <- getWord32
  nhints  <-  getWord32
  LC_TWOLEVEL_HINTS <$> decode fl offset (replicateM (fromIntegral nhints) getTwoLevelHint)

type CommandGetter =
       B.ByteString
       -> B.ByteString
       -> MachoHeader
       -> Decoder LC_COMMAND

loadCommandMap :: Map Word32 CommandGetter
loadCommandMap = Map.fromList
  [ (,) 0x00000001 $ \_ fl  mh -> LC_SEGMENT <$> getSegmentCommand fl mh
  , (,) 0x00000002 $ \_ fl  _  -> getSymTabCommand fl
  , (,) 0x00000004 $ \_  _  _  -> LC_THREAD <$> getThreadCommand
  , (,) 0x00000005 $ \_  _  _  -> LC_THREAD <$> getThreadCommand
  , (,) 0x0000000b $ \_  fl mh -> getDySymTabCommand fl mh
  , (,) 0x0000000c $ \lc _  _  -> getDylibCommand lc LC_LOAD_DYLIB
  , (,) 0x0000000d $ \lc _  _  -> getDylibCommand lc LC_ID_DYLIB
  , (,) 0x0000000e $ \lc _  _  -> LC_LOAD_DYLINKER <$> getLC_STR lc
  , (,) 0x0000000f $ \lc _  _  -> LC_ID_DYLINKER   <$> getLC_STR lc
  , (,) 0x00000010 $ \lc _  _  -> getPreboundDylibCommand lc
  , (,) 0x00000011 $ \_  _  _  -> getRoutinesCommand LC_ROUTINES getWord32
  , (,) 0x00000012 $ \lc _  _  -> LC_SUB_FRAMEWORK <$> getLC_STR lc
  , (,) 0x00000013 $ \lc _  _  -> LC_SUB_UMBRELLA  <$> getLC_STR lc
  , (,) 0x00000014 $ \lc _  _  -> LC_SUB_CLIENT    <$> getLC_STR lc
  , (,) 0x00000015 $ \lc _  _  -> LC_SUB_LIBRARY   <$> getLC_STR lc
  , (,) 0x00000016 $ \_  fl _  -> getTwoLevelHintsCommand fl
  , (,) 0x00000017 $ \_  _  _  -> LC_PREBIND_CKSUM <$> getWord32
  , (,) 0x80000018 $ \lc _  _  -> getDylibCommand lc LC_LOAD_WEAK_DYLIB
  , (,) 0x00000019 $ \_  fl mh -> LC_SEGMENT_64 <$> getSegmentCommand fl mh
  , (,) 0x0000001a $ \_  _  _  -> getRoutinesCommand LC_ROUTINES_64 getWord64
  , (,) 0x0000001b $ \_  _  _  -> lift $ LC_UUID <$> replicateM 8 getWord8
  , (,) 0x8000001c $ \lc _  _  -> LC_RPATH <$> getLC_STR lc
  , (,) 0x0000001d $ \_  _  _  -> LC_CODE_SIGNATURE <$> getWord32 <*> getWord32
  , (,) 0x0000001e $ \_  _  _  -> LC_SEGMENT_SPLIT_INFO <$> getWord32 <*> getWord32
  ]

getLoadCommand :: Word32
               -> B.ByteString
               -> B.ByteString
               -> MachoHeader
               -> LC_COMMAND
getLoadCommand code contents fl mh =
  case Map.lookup code loadCommandMap of
    Nothing ->  LC_UNKNOWN code contents
    Just getter ->
      case runGetOrFail (runDecoder (getter contents fl mh) (mh_magic mh)) (L.fromChunks [contents]) of
        Right (_,_,r) -> r
        Left (_,pos,msg) -> LC_INVALID code contents pos msg

getLoadCommands :: B.ByteString -> MachoHeader -> Decoder [LC_COMMAND]
getLoadCommands fl mh = do
  e <- lift isEmpty
  if e then
    return []
   else do
    cmd     <- getWord32
    cmdsize <- getWord32
    lcdata  <- lift $ getByteString (fromIntegral (cmdsize - 8))
    let lc = getLoadCommand cmd lcdata fl mh
    rest    <- getLoadCommands fl mh
    return $ lc : rest


getRel :: MachoHeader -> Decoder Relocation
getRel mh = do
    r_address <- getWord32
    r_value   <- getWord32
    if (r_address .&. 0x80000000) /= 0 then do
      rs_pcrel   <- (1 ==) <$> bitfield 1 1 r_address
      rs_length  <- (2 ^) <$> bitfield 2 2 r_address
      rs_type    <- bitfield 4 4 r_address
      rs_address <- bitfield 8 24 r_address
      let info = ScatteredRelocationInfo
            { srs_pcrel = rs_pcrel
            , srs_length = rs_length
            , srs_type = fromMaybe (error "Could not parse r_type") $ r_type rs_type (mh_cputype mh)
            , srs_address = rs_address
            , srs_value = fromIntegral r_value
            }
      return $ Scattered info
     else do
      symbolnum <- bitfield 0 24 r_value
      pcrel  <- bitfield 24 1 r_value
      len    <- bitfield 25 2 r_value
      extern <- bitfield 27 1 r_value
      tp     <- bitfield 28 4 r_value
      let info = RelocationInfo { ri_address = fromIntegral r_address
                                , ri_symbolnum = symbolnum
                                , ri_pcrel = pcrel == 1
                                , ri_length = 2 ^ len
                                , ri_extern = extern == 1
                                , ri_type = fromMaybe (error "Could not parse r_type") $ r_type tp (mh_cputype mh)
                                 }
      return $ Unscattered info

getSection :: B.ByteString -> MachoHeader -> Decoder MachoSection
getSection fl mh = do
  sectname  <- lift $ getSectionName
  segname   <- lift $ getSegmentName
  addr      <- getWord
  size      <- getWord
  _offset   <- getWord32
  align     <- getWord32
  reloff    <- getWord32
  nreloc    <- getWord32
  relocs    <- decode fl reloff $ replicateM (fromIntegral nreloc) (getRel mh)
  flags     <- getWord32
  _reserved1 <- getWord32
  _reserved2 <- getWord
  return MachoSection { sec_sectname   = sectname
                      , sec_segname    = segname
                      , sec_addr       = addr
                      , sec_size       = size
                      , sec_align      = 2 ^ align
                      , sec_relocs     = relocs
                      , sec_type       = sectionType flags
                      , sec_user_attrs = sectionUserAttribute flags
                      , sec_sys_attrs  = sectionSystemAttribute flags
                      }

getSegmentCommand :: B.ByteString -> MachoHeader -> Decoder MachoSegment
getSegmentCommand fl mh = do
    segname  <- lift $ getSegmentName
    vmaddr   <- getWord
    vmsize   <- getWord
    fileoff  <- getWord
    filesize <- getWord
    maxprot  <- VM_PROT <$> getWord32
    initprot <- VM_PROT <$> getWord32
    nsects   <- getWord32
    flags    <- SG_FLAGS <$> getWord32
    sects    <- replicateM (fromIntegral nsects) $ getSection fl mh
    return $ MachoSegment { seg_segname = segname
                          , seg_vmaddr  = vmaddr
                          , seg_vmsize  = vmsize
                          , seg_fileoff = fileoff
                          , seg_filesize = filesize
                          , seg_maxprot  = maxprot
                          , seg_initprot = initprot
                          , seg_flags    = flags
                          , seg_sections = sects
                          }


sectionUserAttribute :: Word32 -> [S_USER_ATTR]
sectionUserAttribute flags0 = sectionUserAttribute_ 31 (flags0 .&. 0xff000000)
    where sectionUserAttribute_ :: Int -> Word32 -> [S_USER_ATTR]
          sectionUserAttribute_  0 _ = []
          sectionUserAttribute_ 31 flags | testBit flags 30 = S_ATTR_PURE_INSTRUCTIONS   : sectionUserAttribute_ 30 flags
          sectionUserAttribute_ 30 flags | testBit flags 29 = S_ATTR_NO_TOC              : sectionUserAttribute_ 29 flags
          sectionUserAttribute_ 29 flags | testBit flags 28 = S_ATTR_STRIP_STATIC_SYMS   : sectionUserAttribute_ 28 flags
          sectionUserAttribute_ 28 flags | testBit flags 27 = S_ATTR_NO_DEAD_STRIP       : sectionUserAttribute_ 27 flags
          sectionUserAttribute_ 27 flags | testBit flags 26 = S_ATTR_LIVE_SUPPORT        : sectionUserAttribute_ 26 flags
          sectionUserAttribute_ 26 flags | testBit flags 25 = S_ATTR_SELF_MODIFYING_CODE : sectionUserAttribute_ 25 flags
          sectionUserAttribute_  n flags = sectionUserAttribute_ (n-1) flags

sectionSystemAttribute :: Word32 -> [S_SYS_ATTR]
sectionSystemAttribute flags0 = sectionSystemAttribute_ 31 (flags0 .&. 0x00ffff00)
    where sectionSystemAttribute_ :: Int -> Word32 -> [S_SYS_ATTR]
          sectionSystemAttribute_  0 _ = []
          sectionSystemAttribute_  8 flags | testBit flags 7 = S_ATTR_LOC_RELOC         : sectionSystemAttribute_  7 flags
          sectionSystemAttribute_  9 flags | testBit flags 8 = S_ATTR_EXT_RELOC         : sectionSystemAttribute_  8 flags
          sectionSystemAttribute_ 10 flags | testBit flags 9 = S_ATTR_SOME_INSTRUCTIONS : sectionSystemAttribute_  9 flags
          sectionSystemAttribute_  n flags = sectionSystemAttribute_ (n-1) flags

nullStringAt :: Word32 -> B.ByteString -> B.ByteString
nullStringAt offset = B.takeWhile ((/=) 0) . B.drop (fromIntegral offset)

getLC_STR :: B.ByteString -> Decoder String
getLC_STR lc = do
  offset <- getWord32
  return $ C.unpack $ nullStringAt offset lc

getDylibCommand :: B.ByteString
                -> (String -> Word32 -> Word32 -> Word32 -> LC_COMMAND)
                -> Decoder LC_COMMAND
getDylibCommand lc con = do
  con <$> getLC_STR lc
      <*> getWord32
      <*> getWord32
      <*> getWord32

getPreboundDylibCommand :: B.ByteString -> Decoder LC_COMMAND
getPreboundDylibCommand lc = do
    name           <- getLC_STR lc
    nmodules       <- fromIntegral <$> getWord32
    modules_offset <- fromIntegral <$> getWord32
    let mods = B.unpack $ B.take ((nmodules `div` 8) + (nmodules `mod` 8)) $ B.drop modules_offset lc
    return $ LC_PREBOUND_DYLIB name mods

getThreadCommand :: Decoder [(Word32, [Word32])]
getThreadCommand = do
  e <- lift isEmpty
  if e then
    return []
   else do
    flavor <- getWord32
    count  <- liftM fromIntegral $ getWord32
    state  <- replicateM count getWord32
    rest   <- getThreadCommand
    return ((flavor, state) : rest)

getRoutinesCommand :: (a -> a -> b) -> (Decoder a) -> Decoder b
getRoutinesCommand con dec = do
  init_address <- dec
  init_module  <- dec
  replicateM_ 6 getWord
  return $ con init_address init_module

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

getSymTabCommand :: B.ByteString -> Decoder LC_COMMAND
getSymTabCommand fl = do
  symoff  <- fromIntegral <$> getWord32
  nsyms   <- fromIntegral <$> getWord32
  stroff  <- getWord32
  strsize <- fromIntegral <$> getWord32
  let strsect = B.take strsize $ B.drop (fromIntegral stroff) fl
  symbols <- decode fl symoff $ replicateM nsyms (getNList strsect)
  return $ LC_SYMTAB symbols strsect

getTOC :: Decoder (Word32, Word32)
getTOC = do
  symbol_index <- getWord32
  module_index <- getWord32
  return (symbol_index, module_index)

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
    iinit                 <- return (iinit_iterm .&. 0x0000ffff)
    iterm                 <- return $ (iinit_iterm .&. 0xffff0000) `shiftR` 16
    ninit_nterm           <- getWord32
    ninit                 <- return (ninit_nterm .&. 0x0000ffff)
    nterm                 <- return $ (ninit_nterm .&. 0xffff0000) `shiftR` 16
    is64                  <- is64bit
    (objc_module_info_addr, objc_module_info_size) <-
      if is64 then
        (,) <$> getWord64 <*> getWord32
      else
        (,) <$> getWord   <*> getWord32
    return DylibModule
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

getDySymTabCommand :: B.ByteString
                   -> MachoHeader
                   -> Decoder LC_COMMAND
getDySymTabCommand fl mh = do
    ilocalsym      <- getWord32
    nlocalsym      <- getWord32
    iextdefsym     <- getWord32
    nextdefsym     <- getWord32
    iundefsym      <- getWord32
    nundefsym      <- getWord32
    tocoff         <- getWord32
    ntoc           <- getWord32
    toc            <- decode fl tocoff $ replicateM (fromIntegral ntoc) getTOC
    modtaboff      <- getWord32
    nmodtab        <- getWord32
    modtab         <- decode fl modtaboff $ replicateM (fromIntegral nmodtab) getModule
    extrefsymoff   <- getWord32
    nextrefsyms    <- getWord32
    extrefsyms     <- decode fl extrefsymoff $ replicateM (fromIntegral nextrefsyms) getWord32
    indirectsymoff <- getWord32
    nindirectsyms  <- getWord32
    indirectsyms   <- decode fl indirectsymoff $ replicateM (fromIntegral nindirectsyms) getWord32
    extreloff      <- getWord32
    nextrel        <- getWord32
    extrels        <- decode fl extreloff $ replicateM (fromIntegral nextrel) $ getRel mh
    locreloff      <- getWord32
    nlocrel        <- getWord32
    locrels        <- decode fl locreloff $ replicateM (fromIntegral nlocrel) $ getRel mh
    return $ LC_DYSYMTAB MachoDynamicSymbolTable
        { localSyms    = (ilocalsym, nlocalsym)
        , extDefSyms   = (iextdefsym, nextdefsym)
        , undefSyms    = (iundefsym, nundefsym)
        , tocEntries   = toc
        , modules      = modtab
        , extRefSyms   = extrefsyms
        , indirectSyms = indirectsyms
        , extRels      = extrels
        , locRels      = locrels
        }
