{-|
Provides data structures and functions for working with a dynamic symbol table.
-}
module Data.Macho.Pure.Commands.Dysymtab
  ( DysymtabCommand(..)
    -- ** Table of content entries
  , getTocEntries
  , TOCEntry(..)
    -- ** Modules
  , DylibModule(..)
  , getModules
    -- ** Symbols
  , getExtRefSyms
  , getIndirectSyms
    -- ** Relocations
  , getLocalRelocations
  , getExtRelocations
  ) where

import Data.Bits
import Data.Word

import Data.Macho.Pure.Decoder
import Data.Macho.Pure.Header (MH_MAGIC, magicWordSize)
import Data.Macho.Pure.Relocations

------------------------------------------------------------------------
-- DysymtabCommand

-- | Information stored in the dynamic symbol table command
data DysymtabCommand = DysymtabCommand
    { dysymtabILocalSym  :: !Word32 -- ^ Index to local symbols
    , dysymtabNLocalSym  :: !Word32 -- ^ Number of local symbols
    , dysymtabIExtdefSym :: !Word32 -- ^ Index to externally defined symbols
    , dysymtabNExtdefSym :: !Word32 -- ^ Number of externally defined symbols
    , dysymtabIUndefSym  :: !Word32 -- ^ Index to undefined symbols
    , dysymtabNUndefSym  :: !Word32 -- ^ Number of undefined symbols
    , dysymtabTocOff         :: !FileOffset   -- ^ Offset for symbol table of contents
    , dysymtabTocCount       :: !Word32       -- ^ Number of symbols in contents.
    , dysymtabModtabOff      :: !FileOffset   -- ^ Offset for modules
    , dysymtabModtabCount    :: !Word32       -- ^ Number of modules.
    , dysymtabExtrefSymOff   :: !FileOffset   -- ^ Offset of external symbol reference indices
    , dysymtabExtrefSymCount :: !Word32       -- ^ Number of external reference symbol indices
    , dysymtabIndirectSymOff   :: !FileOffset -- ^ Offset of indirect symbol indices
    , dysymtabIndirectSymCount :: !Word32     -- ^ Number of indirect symbol indices
    , dysymtabExtRelOff     :: !FileOffset   -- ^ External relocation table offset
    , dysymtabExtRelCount   :: !Word32       -- ^ External relocation count
    , dysymtabLocalRelOff   :: !FileOffset   -- ^ Local relocation table offset
    , dysymtabLocalRelCount :: !Word32       -- ^ Local relocation count
    } deriving (Show, Eq)

------------------------------------------------------------------------
-- Table of contents parsers

-- | A table of contents entry provides an association between a
-- symbol and the module it is defined in.
data TOCEntry = TOCEntry { tocSymbol :: {-# UNPACK #-} !Word32
                           -- ^ The index into the symbol table in
                           -- which this entry refers.
                         , tocModule :: {-# UNPACK #-} !Word32
                           -- ^ The index of the module in the module
                           -- table that defines this symbol.
                         }

-- | Get a single
getTOC :: Decoder TOCEntry
getTOC = do
  (\si mi -> TOCEntry { tocSymbol = si, tocModule = mi })
    <$> getWord32
    <*> getWord32

-- | Get table of content entries from file.
getTocEntries :: MachoFile -> DysymtabCommand -> Maybe [TOCEntry]
getTocEntries mfile cmd =
  getTable mfile (dysymtabTocOff cmd) (dysymtabTocCount cmd) 8 getTOC

------------------------------------------------------------------------
-- Local relocations

-- | Return list of relocations.
getLocalRelocations :: MachoFile -> DysymtabCommand -> Maybe [Relocation]
getLocalRelocations mfile cmd =
  getRelocations mfile (dysymtabLocalRelOff cmd) (dysymtabLocalRelCount cmd)


------------------------------------------------------------------------
-- DylibModule

-- | Information about a module imported by a dynamic symbol table.
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

-- | Module size
dylibModuleSize :: MH_MAGIC -> Word32
dylibModuleSize magic = 12 * 4 + magicWordSize magic


-- | Get modules entries referenced  by symbol table command.
getModules :: MachoFile -> DysymtabCommand -> Maybe [DylibModule]
getModules mfile cmd =
  getTable mfile (dysymtabModtabOff cmd) (dysymtabModtabCount cmd)
           (dylibModuleSize (machoMagic mfile)) getModule

------------------------------------------------------------------------
-- Other parsers

-- | List of external reference symbol indices
getExtRefSyms :: MachoFile -> DysymtabCommand -> Maybe [Word32]
getExtRefSyms mfile cmd =
  getTable mfile (dysymtabExtrefSymOff cmd) (dysymtabExtrefSymCount cmd) 4 getWord32

-- | List of external refernce symbol indices
getIndirectSyms :: MachoFile -- ^ Contents of MachoFile
                -> DysymtabCommand
                -> Maybe [Word32]
getIndirectSyms mfile cmd =
  getTable mfile (dysymtabIndirectSymOff cmd) (dysymtabIndirectSymCount cmd) 4 getWord32

-- | List of external locations
getExtRelocations :: MachoFile -- ^ Contents of MachoFile
                  -> DysymtabCommand
                  -> Maybe [Relocation]
getExtRelocations mfile cmd = getRelocations mfile (dysymtabExtRelOff cmd) (dysymtabExtRelCount cmd)
