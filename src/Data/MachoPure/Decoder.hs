{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Data.MachoPure.Decoder
  ( Decoder
  , doDecode
  , binary
  , is64bit
  , bitfield
  , lift
  , getWord
  , getWord16
  , getWord32
  , getWord64
  , _getWord32
  , nullStringAt
  , getLC_STR
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

import           Data.MachoPure.Header

bitfield_le :: Int -> Int -> Word32 -> Word32
bitfield_le off sz word = (word `shiftL` (32 - (off + sz))) `shiftR` (32 - sz)

bitfield_be :: Int -> Int -> Word32 -> Word32
bitfield_be off sz word = (word `shiftL` off) `shiftR` (32 - sz)

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

------------------------------------------------------------------------
-- Decoder

-- | A decoder that can read at the given width.
newtype Decoder a = Decoder { runDecoder :: ReaderT MH_MAGIC Get a }
  deriving (Functor, Applicative, Monad)

binary :: Decoder MH_MAGIC
binary = Decoder ask

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

getWord16 :: Decoder Word16
getWord16 = lift . _getWord16 =<< binary

getWord32 :: Decoder Word32
getWord32 = lift . _getWord32 =<< binary

getWord64 :: Decoder Word64
getWord64 = lift . _getWord64 =<< binary

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
