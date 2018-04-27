{-|
This provides interfaces for parsing Macho and FAT files.
-}
{-# LANGUAGE PatternGuards #-}
module Data.Macho.Pure
  ( -- * Top-level parsers
    parseMagic
  , parseMacho
  , ParseMachoError(..)
  , ParseMagicError(..)
  , Data.Macho.Pure.Decoder.MachoFile
    -- * Header
  , module Data.Macho.Pure.Header
    -- * Commands
  , module Data.Macho.Pure.Commands
    -- * Symbols
  , module Data.Macho.Pure.Symbols
    -- * Relocations
  , module Data.Macho.Pure.Relocations
    -- * Two-level Hints
  , getTwoLevelHints
    -- * Multi-architecture (fat) files
  , module Data.Macho.Pure.FAT
  ) where

import           Data.Macho.Pure.Commands
import           Data.Macho.Pure.Decoder
import           Data.Macho.Pure.FAT
import           Data.Macho.Pure.Header
import           Data.Macho.Pure.Relocations
import           Data.Macho.Pure.Symbols

import           Control.Monad
import           Data.Binary hiding (decode)
import           Data.Binary.Get hiding (Decoder)
import qualified Data.ByteString as B
import           Numeric

-- | Number of bytes in a macho header
headerSize :: MH_MAGIC -> Int
-- The header contains 7 32-bit fields, and 64-bit files contain an extra
-- 4 bytes of padding.
headerSize magic = if magicIs64Bit magic then 32 else 28

-- | The errors that can occur from parsing the magic constant.
data ParseMagicError
   = InsufficientMagicBytes
     -- ^ The magic value could not be parsed
   | UnknownMagic !Word32
     -- ^ The magic value was unknown

instance Show ParseMagicError where
  show InsufficientMagicBytes = "The file did not contain a 4-byte file identifier."
  show (UnknownMagic v) =
    "The first four bytes 0x" ++ showHex v " do not identify a known file type."

-- | The header along with number of commands and size of commands.
type HeaderParseResult = (MachoHeader, Word32, Word32)

-- | Return the header along with number of commands and size of commands.
getMachoHeader :: MH_MAGIC -> Get HeaderParseResult
getMachoHeader magic = do
  let end = magicEndianness magic
  cputype    <- CPU_TYPE <$> _getWord32 end
  cpusubtype <- CPU_SUBTYPE <$> _getWord32 end
  filetype   <- MH_FILETYPE <$> _getWord32 end

  ncmds      <- _getWord32 end
  sizeofcmds <- _getWord32 end

  flags      <- MH_FLAGS <$> _getWord32 end

  let hdr = MachoHeader { mh_magic = magic
                        , mh_cputype = cputype
                        , mh_cpusubtype = cpusubtype
                        , mh_filetype = filetype
                        , mh_flags = flags
                        }
  return (hdr, ncmds, sizeofcmds)

-- | Common type for identifying Macho and FAT files.
data Magic
   = MachoMagic !MH_MAGIC
   | FatMagic !FAT_MAGIC_TYPE

-- | Just parse just the 4-byte magic value used to identify Mach-o files.
parseMagic :: B.ByteString -> Either ParseMagicError Magic
parseMagic s = do
  when (B.length s < 4) $ do
    Left $ InsufficientMagicBytes
  let Just magicVal = tryRunGet s getWord32le
  case () of
    _ | Just magic <- magicFromWord32LE magicVal ->
          Right $! MachoMagic magic
      | Just magic <- fatMagicFromWord32LE magicVal ->
          Right $! FatMagic magic
      | otherwise ->
          Left $! UnknownMagic magicVal

-- | Parse the Macho header
parseHeader :: B.ByteString -> Either ParseMachoError HeaderParseResult
parseHeader s = do
  when (B.length s < 4) $ do
    Left $ InsufficientHeaderBytes
  let Just magicVal = tryRunGet s getWord32le

  magic <-
    case magicFromWord32LE magicVal of
      Just m -> pure m
      Nothing -> Left $ NotMachoMagic magicVal

  -- Check complete length
  when (B.length s <= headerSize magic) $ do
    Left $ InsufficientHeaderBytes
  -- Read rest of header.
  let Just r = tryRunGet (B.drop 4 s) (getMachoHeader magic)
  pure r

getTwoLevelHint :: Decoder (Word32, Word32)
getTwoLevelHint = do
  word <- getWord32
  isub_image <- bitfield 0 8 word
  itoc       <- bitfield 8 24 word
  return (isub_image, itoc)

-- | This returns the two level hints entry or Nothing if the buffer is not large enough.
getTwoLevelHints :: MachoFile -> FileOffset -> Word32 -> Maybe [(Word32, Word32)]
getTwoLevelHints mfile off cnt = getTable mfile off cnt 4 getTwoLevelHint

------------------------------------------------------------------------
-- parseMacho

-- | An error that occured in parsing the header or commands.
data ParseMachoError
   = NotMachoMagic !Word32
     -- ^ An error occured in parsing magic.
   | InsufficientHeaderBytes
     -- ^ There were not enough bytes for header.
   | CommandError !ByteOffset !String
     -- ^ An error occured in parsing a command

instance Show ParseMachoError where
  show (NotMachoMagic v) =
    "The first four bytes 0x" ++ showHex v " do not identify a Macho file."
  show InsufficientHeaderBytes = "File does not contain a complete header."
  show (CommandError pos msg) = "Could not decode commands at pos " ++ show pos ++ ": " ++ msg

-- | Parse a ByteString into data structures for representing file
-- bytes, header, and list of commands.
parseMacho :: B.ByteString -> Either ParseMachoError (MachoFile, MachoHeader, [LC_COMMAND])
parseMacho b = do
  (header, ncmds, sizeofcmds) <- parseHeader b
  let magic = mh_magic header
  let loadCommandBuffer = B.take (fromIntegral sizeofcmds) $ B.drop (headerSize magic) b
  case parseCommands magic ncmds loadCommandBuffer of
    Left (pos,msg) -> do
      Left $ CommandError pos msg
    Right commands -> do
      let mfile = MachoFile { machoMagic = mh_magic header
                            , machoContents = b
                            }
      Right $ (mfile, header, commands)
