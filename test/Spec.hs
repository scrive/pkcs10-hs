module Main where

import           Control.Monad
import           Crypto.Hash
import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.RSA        as RSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as BC
import           Data.PEM
import           Data.X509
import           Data.X509.PKCS10
import           Keys
import           Test.QuickCheck.Monadic  (monadicIO, run, assert)
import           Test.Tasty
import           Test.Tasty.HUnit hiding (assert)
import           Test.Tasty.QuickCheck

main :: IO ()
main = do
  defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [properties, unitTests]

properties :: TestTree
properties = testGroup "Properties" [qcProps]

unitTests = testGroup "Unit tests"
  [ testCase "CSR with subject and extension (RSA)" $ do
     req <- defaultRsaCSR subjectAttrs extAttrs
     checkCSR (csrToSigned req) subjectAttrs extAttrs
  , testCase "CSR with empty subject and extension (RSA)" $ do
      req <- defaultRsaCSR emptySubjectAttrs emptyExtAttrs
      checkCSR (csrToSigned req) emptySubjectAttrs emptyExtAttrs
  , testCase "CSR fixtures (RSA)" $ do
      checkRsaFixtureCSR "rsa1" pemSubjectAttrs pemExtAttrs
      checkRsaFixtureCSR "rsa2" pemSubjectAttrs emptyExtAttrs
      checkRsaFixtureCSR "rsa3" emptySubjectAttrs emptyExtAttrs
  , testCase "CSR with subject and extension (DSA)" $ do
      req <- defaultDsaCSR subjectAttrs extAttrs
      checkCSR (csrToSigned req) subjectAttrs extAttrs
  ,  testCase "CSR with empty subject and extension (DSA)" $ do
      req <- defaultDsaCSR emptySubjectAttrs emptyExtAttrs
      checkCSR (csrToSigned req) emptySubjectAttrs emptyExtAttrs
  , testCase "CSR fixtures (DSA)" $ do
      checkRsaFixtureCSR "dsa1" pemSubjectAttrs pemExtAttrs
      checkRsaFixtureCSR "dsa2" pemSubjectAttrs emptyExtAttrs
      checkRsaFixtureCSR "dsa3" emptySubjectAttrs emptyExtAttrs
  ]

qcProps = testGroup "(checked by QuickCheck)"
  [ testProperty "CSR" (property_csr) ]

subjectAttrs = makeX520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]

pemSubjectAttrs = X520Attributes [(X520CommonName, asn1CharacterString Printable "api"), (X520CommonName, asn1CharacterString Printable "fcomb"), (X520CommonName, asn1CharacterString Printable "com"), (X520StateOrProvinceName, asn1CharacterString Printable "Moscow"), (X520LocalityName, asn1CharacterString Printable "Moscow"), (X520OrganizationName, asn1CharacterString Printable "End Point"), (X520OrganizationalUnitName, asn1CharacterString Printable "fcomb"), (EmailAddress, asn1CharacterString IA5 "in@fcomb.io"), (X509SubjectAltName, asn1CharacterString Printable "DNS.1=fcomb.com")]

emptySubjectAttrs = X520Attributes []

extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtExtendedKeyUsage [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_CodeSigning], PKCS9Attribute $ ExtKeyUsage [KeyUsage_digitalSignature, KeyUsage_cRLSign]]

pemExtAttrs = PKCS9Attributes [PKCS9Attribute $ ExtBasicConstraints False Nothing, PKCS9Attribute $ ExtKeyUsage [KeyUsage_digitalSignature,KeyUsage_nonRepudiation,KeyUsage_keyEncipherment]]

emptyExtAttrs = PKCS9Attributes []

instance Arbitrary PubKey where
  arbitrary = elements [PubKeyRSA rsaPublicKey, PubKeyDSA dsaPublicKey]

instance Arbitrary ASN1StringEncoding where
  arbitrary = elements [IA5,UTF8,Printable,Visible]

instance Arbitrary X520Attribute where
  arbitrary = elements [X520CommonName,X520SerialNumber,X520Name,X520Surname,X520GivenName,X520Initials,X520GenerationQualifier,X520CountryName,X520LocalityName,X520StateOrProvinceName,X520StreetAddress,X520OrganizationName,X520OrganizationalUnitName,X520Title,X520DNQualifier,X520Pseudonym,X509SubjectAltName,EmailAddress,IPAddress,DomainComponent,UserId,RawAttribute [1,2,3,4,5]]

arbitraryX520Attrs r1 r2 =
  choose (r1,r2) >>= \l -> replicateM l arbitraryAttr
  where
    arbitraryAttr = (,) <$> arbitrary <*> arbitrary

instance Arbitrary X520Attributes where
  arbitrary = X520Attributes <$> arbitraryX520Attrs 0 15

arbitraryBS r1 r2 = choose (r1,r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

instance Arbitrary ASN1CharacterString where
  arbitrary = ASN1CharacterString <$> arbitrary <*> arbitraryBS 1 36

property_csr subjectAttrs pubKey = monadicIO $ do
  req <- run $ case pubKey of
                PubKeyRSA _ -> defaultRsaCSR subjectAttrs pemExtAttrs
                PubKeyDSA _ -> defaultDsaCSR subjectAttrs pemExtAttrs
                _ -> undefined
  check <- run $ checkCSR (csrToSigned req) subjectAttrs pemExtAttrs
  assert $ check == ()

readRSA pem = PubKeyRSA $ readRsaPubKey pem 256

readDSA pem = PubKeyDSA $ readDsaPubKey pem

checkRsaFixtureCSR csrName subjectAttrs extAttrs = do
  csrPem <- readPEMFile $ "test/fixtures/" ++ csrName ++ ".csr"
  checkCSR (readCSR csrPem) subjectAttrs extAttrs

defaultRsaCSR subjectAttrs extAttrs = do
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairRSA rsaPublicKey rsaPrivateKey) SHA512
  return req

defaultDsaCSR subjectAttrs extAttrs = do
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairDSA dsaPublicKey dsaPrivateKey) SHA1
  return $ req

readPEMFile file = do
  content <- B.readFile file
  return $ either error (pemContent . head) $ pemParseBS content

decodeFromDER :: ASN1Object o => BC.ByteString -> Either String (o, [ASN1])
decodeFromDER bs =
  f asn
  where
    asn = fromASN1 <$> decodeASN1' DER bs
    f = either (Left . show) id

checkAttrs csr subjectAttrs extAttrs = do
  let certReqInfo = certificationRequestInfo csr
  assertBool "subject == subjectAttrs" $
    (subject certReqInfo) == subjectAttrs
  assertBool "attributes == extAttrs" $
    (attributes certReqInfo) == extAttrs

checkDER csr = do
  let (Right csr') = (fromDER . encodeToDER) csr
  assertBool "DER: csr' == csr" $ (certificationRequest csr') == csr

checkPEM csr = do
  let (Right csr') = (fromPEM . toPEM) csr
  assertBool "PEM: csr' == csr" $ (certificationRequest csr') == csr
  let (Right csr'') = (fromPEM . toNewFormatPEM) csr
  assertBool "PEM: csr'' == csr" $
    (certificationRequest csr'') == csr
  assertBool "pemName == CERTIFICATE REQUEST" $
    (pemName . toPEM $ csr) == "CERTIFICATE REQUEST"
  assertBool "pemName == NEW CERTIFICATE REQUEST" $
    (pemName . toNewFormatPEM $ csr) == "NEW CERTIFICATE REQUEST"

verifyCSR csr = do
  assertBool "verify csr" $ verify csr
  let cri = (certificationRequest csr) {
    signature = Signature $ BC.pack "invalid"
  }
  let csr' = csr { certificationRequest = cri }
  assertBool "verify not valid csr" $ not $ verify csr'

checkCSR csr subjectAttrs extAttrs = do
  checkAttrs (certificationRequest csr) subjectAttrs extAttrs
  checkDER (certificationRequest csr)
  checkPEM (certificationRequest csr)
  verifyCSR csr

readRsaPubKey :: B.ByteString -> Int -> RSA.PublicKey
readRsaPubKey bs size =
  case decodeASN1' DER bs of
    Right (Start Sequence :
           IntVal _ :
           IntVal public_n :
           IntVal public_e :
           IntVal private_d :
           IntVal private_p :
           IntVal private_q :
           IntVal private_dP :
           IntVal private_dQ :
           IntVal private_qinv :
           End Sequence : _) ->
           RSA.private_pub $ RSA.PrivateKey {
                  RSA.private_pub = RSA.PublicKey {
                    RSA.public_size = size
                  , RSA.public_n = public_n
                  , RSA.public_e = public_e
                  }
                , RSA.private_d = private_d
                , RSA.private_p = private_p
                , RSA.private_q = private_q
                , RSA.private_dP = private_dP
                , RSA.private_dQ = private_dQ
                , RSA.private_qinv = private_qinv
           }
    _ -> error "RSA.PrivateKey: unknown format"

readDsaPubKey :: B.ByteString -> DSA.PublicKey
readDsaPubKey bs =
  case decodeASN1' DER bs of
    Right (Start Sequence :
           IntVal _ :
           IntVal params_p :
           IntVal params_q :
           IntVal params_g :
           IntVal public_y :
           IntVal _ : -- private_x :
           End Sequence : _) ->
           DSA.PublicKey {
             DSA.public_y = public_y
           , DSA.public_params = DSA.Params {
               DSA.params_p = params_p
             , DSA.params_g = params_g
             , DSA.params_q = params_q
             }
           }
    _ -> error "DSA.PrivateKey: unknown format"

readCSR bs =
  case fromDER bs of
    Right (scr@SignedCertificationRequest {}) -> scr
    Left e -> error . show $ e
