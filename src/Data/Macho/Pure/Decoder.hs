{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Data.Macho.Pure.Decoder
  ( -- * Decoder
    Decoder
  , doDecode
  , binary
  , is64bit
  , bitfield
  , lift
  , getWord
  , Data.Macho.Pure.Decoder.getWord8
  , getWord16
  , getWord32
  , getWord64
  , nullStringAt
  , getLC_STR
    -- * Specific function
  , Endianness(..)
  , magicEndianness
  , _getWord32
    -- * MachoFile
  , MachoFile(..)
  , getTable
    -- * Utilities
  , FileOffset(..)
  , subbuffer
  , tryRunGet
  ) where

import           Control.Monad.Reader hiding (lift)
import qualified Control.Monad.Reader
import           Data.Binary.Get hiding (Decoder)
import           Data.Binary.Put
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as L
import           Data.Word

import           Data.Macho.Pure.Header


-- | This runs a getter on a strict bytestring and returns the result
-- if it does not fail.
tryRunGet :: B.ByteString -> Get a -> Maybe a
tryRunGet s a =
  case runGetOrFail a (L.fromChunks [s]) of
    Left{} -> Nothing
    Right (_,_,v) -> Just v

bitfield_le :: Int -> Int -> Word32 -> Word32
bitfield_le off sz word = (word `shiftL` (32 - (off + sz))) `shiftR` (32 - sz)

bitfield_be :: Int -> Int -> Word32 -> Word32
bitfield_be off sz word = (word `shiftL` off) `shiftR` (32 - sz)

------------------------------------------------------------------------
-- Endian specific operations.

data Endianness = LittleEndian | BigEndian
  deriving (Eq)

_getWord16 :: Endianness -> Get Word16
_getWord16 LittleEndian = getWord16le
_getWord16    BigEndian = getWord16be

_getWord32 :: Endianness -> Get Word32
_getWord32 LittleEndian = getWord32le
_getWord32    BigEndian = getWord32be

_getWord64 :: Endianness -> Get Word64
_getWord64 LittleEndian = getWord64le
_getWord64    BigEndian = getWord64be

_putWord16 :: MH_MAGIC -> Word16 -> Put
_putWord16 m = if magicIsLittleEndian m then putWord16le else putWord16be

_putWord32 :: MH_MAGIC -> Word32 -> Put
_putWord32 m = if magicIsLittleEndian m then putWord32le else putWord32be

_putWord64 :: MH_MAGIC -> Word64 -> Put
_putWord64 m = if magicIsLittleEndian m then putWord64le else putWord64be

------------------------------------------------------------------------
-- FileOffset

newtype FileOffset = FileOffset { fileOffsetValue :: Word32 }
  deriving (Eq)

instance Show FileOffset where
  show = show . fileOffsetValue

------------------------------------------------------------------------
-- Decoder

-- | A decoder that can read at the given width.
newtype Decoder a = Decoder { runDecoder :: ReaderT MH_MAGIC Get a }
  deriving (Functor, Applicative, Monad)

binary :: Decoder MH_MAGIC
binary = Decoder ask

magicEndianness :: MH_MAGIC -> Endianness
magicEndianness m = if magicIsLittleEndian m then LittleEndian else BigEndian

doDecode :: MH_MAGIC
         -> B.ByteString
         -> Decoder a
         -> Either (L.ByteString, ByteOffset, String)
                   (L.ByteString, ByteOffset, a)
doDecode m b d = runGetOrFail (runReaderT (runDecoder d) m) (L.fromChunks [b])

getWord :: Decoder Word64
getWord = do
  is64 <- is64bit
  if is64 then getWord64 else fromIntegral <$> getWord32

lift :: Get a -> Decoder a
lift = Decoder . Control.Monad.Reader.lift

is64bit :: Decoder Bool
is64bit = magicIs64Bit <$> binary

getWord8 :: Decoder Word8
getWord8 = lift Data.Binary.Get.getWord8

getWord16 :: Decoder Word16
getWord16 = lift . _getWord16 . magicEndianness =<< binary

getWord32 :: Decoder Word32
getWord32 = lift . _getWord32 . magicEndianness =<< binary

getWord64 :: Decoder Word64
getWord64 = lift . _getWord64 . magicEndianness =<< binary

bitfield  :: Int -> Int -> Word32 -> Decoder Word32
bitfield off sz word = do
  m <- binary
  pure $ if magicIsLittleEndian m then bitfield_le off sz word else bitfield_be off sz word

nullStringAt :: Word32 -> B.ByteString -> B.ByteString
nullStringAt offset = B.takeWhile ((/=) 0) . B.drop (fromIntegral offset)

-- | This reads a null terminated string from a
getLC_STR :: B.ByteString -> Decoder String
getLC_STR lc = do
  offset <- getWord32
  return $ C.unpack $ nullStringAt offset lc

------------------------------------------------------------------------
-- MachoFile

-- | Information needed to read structure out of a Mach-O file
data MachoFile = MachoFile { machoMagic :: !MH_MAGIC
                             -- ^ Magic value at start of mach-o file.
                           , machoContents :: !B.ByteString
                             -- ^ Complete contents of the Mach-o file.
                           }

-- | Return a slice of the given buffer at the offset and size.
subbuffer :: B.ByteString -> FileOffset -> Word32 -> Maybe B.ByteString
subbuffer b (FileOffset o) c = do
  when (toInteger (B.length b) < toInteger o + toInteger c) $
    Nothing
  Just $ B.take (fromIntegral c) $ B.drop (fromIntegral o) b

-- | This runs a decoder for a fixed size type on a contiguous set of
-- values.
--
-- It returns the list if it could be parsed, and `Nothing` if it
-- could not.
getTable :: MachoFile
         -> FileOffset -- ^ Offset of table in contents
         -> Word32 -- ^ Number of entries in table
         -> Word32 -- ^ Size of each element in table.
         -> Decoder a -- ^ Decoder for each element in table
         -> Maybe [a]
getTable mFile off cnt sz dec = do
  when (cnt >= (maxBound :: Word32) `div` sz) $ Nothing
  buf <- subbuffer (machoContents mFile) off (sz*cnt)
  case doDecode (machoMagic mFile) buf (replicateM (fromIntegral cnt) dec) of
    Left (_rest,errOff,msg) ->
      error $ "internal: getTable encountered unexpected error at offset" ++ show errOff ++ "\n  "
        ++ msg
    Right (_,_,v) -> Just v
