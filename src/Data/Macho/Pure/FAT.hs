{-|
Information for parsing FAT files.
-}
{-# LANGUAGE PatternSynonyms #-}
module Data.Macho.Pure.FAT
  ( FatHeader(..)
  , FAT_MAGIC_TYPE
  , pattern FAT_MAGIC
  , pattern FAT_CIGAM
  , fatMagicFromWord32LE
  , FatArch(..)
  , parseFatHeader
  , FatError(..)
  ) where

import           Data.Macho.Pure.Decoder
import           Data.Macho.Pure.Header

import           Control.Monad
import           Data.Binary.Get
import qualified Data.ByteString as BS
import           Data.Word

-- | An identifier for a fat file.
newtype FAT_MAGIC_TYPE = FAT_MAGIC_TYPE { fatMagicValue :: Word32 }
  deriving (Eq, Ord)

-- | A little endian FAT file magic identifier.
pattern FAT_MAGIC :: FAT_MAGIC_TYPE
pattern FAT_MAGIC = FAT_MAGIC_TYPE 0xcafebabe

-- | A big endian FAT file magic identifier.
pattern FAT_CIGAM :: FAT_MAGIC_TYPE
pattern FAT_CIGAM = FAT_MAGIC_TYPE 0xbebafeca

{-# COMPLETE FAT_MAGIC, FAT_CIGAM #-}

-- | Create magic from Word32 read in little-bit endian order or return
-- `Nothing` if it is not a valid magic value.
fatMagicFromWord32LE :: Word32 -> Maybe FAT_MAGIC_TYPE
fatMagicFromWord32LE w
  | w == fatMagicValue FAT_MAGIC = Just FAT_MAGIC
  | w == fatMagicValue FAT_CIGAM = Just FAT_CIGAM
  | otherwise = Nothing

fatMagicEndianness :: FAT_MAGIC_TYPE -> Endianness
fatMagicEndianness FAT_MAGIC = LittleEndian
fatMagicEndianness FAT_CIGAM = BigEndian

data FatArch = FatArch
  { faCpuType    :: !CPU_TYPE
  , faCpuSubtype :: !CPU_SUBTYPE
  , faOffset     :: !Word32
  , faSize       :: !Word32
  , faAlign      :: !Word32
  }

fatArchSize :: Int
fatArchSize = 5 * 4

getFatArch :: Endianness -> Get FatArch
getFatArch end = do
  cputype    <- CPU_TYPE <$> _getWord32 end
  cpusubtype <- CPU_SUBTYPE <$> _getWord32 end
  offset <- _getWord32 end
  size   <- _getWord32 end
  align  <- _getWord32 end
  pure $!
    FatArch { faCpuType = cputype
            , faCpuSubtype = cpusubtype
            , faOffset = offset
            , faSize = size
            , faAlign = align
            }

data FatHeader = FatHeader
  { fhMagic :: !FAT_MAGIC_TYPE
  , fhArchitectures :: ![FatArch]
  }

data FatError
   = BadMagic !BS.ByteString
     -- ^ The magic value is not valid.
   | FatUnexpectedEndOfFile

parseFatMagic :: BS.ByteString -> Either FatError (FAT_MAGIC_TYPE, BS.ByteString)
parseFatMagic s = do
  when (BS.length s < 4) $ do
    Left $ BadMagic s
  case fatMagicFromWord32LE =<< tryRunGet s getWord32le of
    Nothing -> Left $ BadMagic (BS.take 4 s)
    Just mag -> pure (mag, BS.drop 4 s)

fatHeaderSize :: Word32 -> Int
fatHeaderSize archCnt = 8 + fromIntegral archCnt * fatArchSize

parseFatHeader :: BS.ByteString -> Either FatError FatHeader
parseFatHeader s = do
  when (BS.length s < 8) $ do
    Left $ FatUnexpectedEndOfFile
  (magic, s1) <- parseFatMagic s

  let end = fatMagicEndianness magic

  let Just archCnt = tryRunGet s1 $ _getWord32 end

  when (BS.length s < fatHeaderSize archCnt) $ do
    Left $ FatUnexpectedEndOfFile
  let Just arches = tryRunGet (BS.drop 8 s) $ do
                 replicateM (fromIntegral archCnt) (getFatArch end)
  pure $! FatHeader { fhMagic = magic
                    , fhArchitectures = arches
                    }
