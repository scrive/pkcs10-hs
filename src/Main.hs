{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Applicative      ((<$>), (<*>))
import           Control.Monad
import           Crypto.Hash
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.BitArray
import           Data.ASN1.Encoding
import           Data.ASN1.OID
import           Data.ASN1.Types
import           Data.Bits
import           Data.ByteArray.Encoding
import qualified Data.ByteString          as B
import qualified Data.ByteString.Base64   as Base64
import qualified Data.ByteString.Char8    as BC
import qualified Data.ByteString.Lazy     as L
import           Data.PEM                 (pemContent, pemName, pemParseBS)
import           Data.X509
import           Data.X509.File
import           Data.X509.Memory
import           Numeric
import           Text.Printf

publicExponent :: Integer
publicExponent = 0x10001 -- 65537

rsaKeySize :: Int
rsaKeySize = 256 -- 2048 bits

data X520Attribute =
     X520CommonName
     | X520SerialNumber
     | X520Name
     | X520Surname
     | X520GivenName
     | X520Initials
     | X520GenerationQualifier
     | X520CountryName
     | X520LocalityName
     | X520StateOrProvinceName
     | X520StreetAddress
     | X520OrganizationName
     | X520OrganizationalUnitName
     | X520Title
     | X520DNQualifier
     | X520Pseudonym
     | EmailAddress
     | IPAddress
     | DomainComponent
     | UserId
     deriving (Show, Eq)

oidPrefix :: [Integer]
oidPrefix = [2,5,4]

instance OIDable X520Attribute where
  getObjectID X520CommonName             = oidPrefix ++ [3]
  getObjectID X520SerialNumber           = oidPrefix ++ [5]
  getObjectID X520Name                   = oidPrefix ++ [41]
  getObjectID X520Surname                = oidPrefix ++ [4]
  getObjectID X520GivenName              = oidPrefix ++ [42]
  getObjectID X520Initials               = oidPrefix ++ [43]
  getObjectID X520GenerationQualifier    = oidPrefix ++ [44]
  getObjectID X520CountryName            = oidPrefix ++ [6]
  getObjectID X520LocalityName           = oidPrefix ++ [7]
  getObjectID X520StateOrProvinceName    = oidPrefix ++ [8]
  getObjectID X520StreetAddress          = oidPrefix ++ [9]
  getObjectID X520OrganizationName       = oidPrefix ++ [10]
  getObjectID X520OrganizationalUnitName = oidPrefix ++ [11]
  getObjectID X520Title                  = oidPrefix ++ [12]
  getObjectID X520DNQualifier            = oidPrefix ++ [46]
  getObjectID X520Pseudonym              = oidPrefix ++ [65]
  getObjectID EmailAddress               = [1,2,840,113549,1,9,1]
  getObjectID IPAddress                  = [1,3,6,1,4,1,42,2,11,2,1]
  getObjectID DomainComponent            = [0,9,2342,19200300,100,1,25]
  getObjectID UserId                     = [0,9,2342,19200300,100,1,1]

newtype X520Attributes =
        X520Attributes [(X520Attribute, String)] deriving (Show, Eq)

data CertificationRequest = CertificationRequest {
  certificationRequestInfo :: CertificationRequestInfo
  , signatureAlgorithm     :: SignatureAlgorithmIdentifier
  , signature              :: Signature
} deriving (Show, Eq)

data CertificationRequestInfo = CertificationRequestInfo {
  version                :: Version
  , subject              :: X520Attributes
  , subjectPublicKeyInfo :: PubKey
  -- , attributes           ::
} deriving (Show, Eq)

newtype Version = Version Int deriving (Show, Eq)

data SignatureAlgorithmIdentifier =
     SignatureAlgorithmIdentifier SignatureALG deriving (Show, Eq)

newtype Signature =
        Signature B.ByteString deriving (Show, Eq)

instance ASN1Object CertificationRequest where
  toASN1 (CertificationRequest info sigAlg sig) xs = do
    Start Sequence :
      (toASN1 info []) ++
      (toASN1 sigAlg []) ++
      (toASN1 sig []) ++
      End Sequence : xs

  fromASN1 = undefined

instance ASN1Object Signature where
  toASN1 (Signature bs) xs =
    (BitString $ toBitArray bs 0) : xs

  fromASN1 = undefined

instance ASN1Object CertificationRequestInfo where
  toASN1 (CertificationRequestInfo version subject pubKey) xs =
    Start Sequence :
      (toASN1 version []) ++
      (toASN1 subject []) ++
      (toASN1 pubKey []) ++
      [Start (Container Context 0), End (Container Context 0)] ++
      End Sequence : xs

  fromASN1 = undefined

instance ASN1Object Version where
  toASN1 (Version v) xs =
    [IntVal $ fromIntegral v] ++ xs

  fromASN1 = undefined

instance ASN1Object X520Attributes where
  toASN1 (X520Attributes attrs) xs = do
    Start Sequence :
      attrSets ++
      End Sequence : xs
    where
      attrSets = concatMap f attrs
      f (attr, s) = [Start Set, Start Sequence, oid attr, cs s, End Sequence, End Set]
      oid attr = OID $ getObjectID attr
      cs s = ASN1String $ asn1CharacterString UTF8 s

  fromASN1 = undefined

instance ASN1Object SignatureAlgorithmIdentifier where
  toASN1 (SignatureAlgorithmIdentifier sigAlg) = toASN1 sigAlg

  fromASN1 = undefined

main :: IO ()
main = do
     (pubKey, privKey) <- RSA.generate rsaKeySize publicExponent

     let certificationRequestInfo = CertificationRequestInfo {
       version = Version 0
       , subject = X520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]
       , subjectPublicKeyInfo = PubKeyRSA pubKey
     }
     let scratch = encodeASN1' DER $ toASN1 certificationRequestInfo []
     Right signature <- RSA.signSafer (Just SHA256) privKey scratch
     let req = CertificationRequest {
       certificationRequestInfo = certificationRequestInfo
       , signatureAlgorithm = SignatureAlgorithmIdentifier (SignatureALG HashSHA256 PubKeyALG_RSA)
       , signature = Signature signature
     }
     let reqASN = toASN1 req []
     let bits = encodeASN1' DER $ reqASN
     B.writeFile "/tmp/pkcs10.der" bits
     return ()