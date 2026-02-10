PKCS#10 library
=========

[![CI](https://github.com/scrive/pkcs10-hs/actions/workflows/haskell-ci.yml/badge.svg?branch=master)](https://github.com/scrive/pkcs10-hs/actions/workflows/haskell-ci.yml)
[![Hackage](https://img.shields.io/hackage/v/pkcs10.svg)](https://hackage.haskell.org/package/pkcs10)
[![Stackage LTS](https://www.stackage.org/package/pkcs10/badge/lts)](https://www.stackage.org/lts/package/pkcs10)
[![Stackage Nightly](https://www.stackage.org/package/pkcs10/badge/nightly)](https://www.stackage.org/nightly/package/pkcs10)

### Example

```haskell
import           Crypto.Hash
import           Crypto.PubKey.RSA
import           Data.X509
import           Data.X509.PKCS10

main :: IO ()
main = do
  let rsaKeySize = 128
  let publicExponent = 3
  (pubKey, privKey) <- generate rsaKeySize publicExponent
  let subjectAttrs = makeX520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]
  let extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtBasicConstraints False Nothing, PKCS9Attribute $ ExtKeyUsage [KeyUsage_digitalSignature,KeyUsage_nonRepudiation,KeyUsage_keyEncipherment]]
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairRSA pubKey privKey) SHA512
  putStrLn . show . toPEM $ req -- export in PEM format
  putStrLn . show $ verify (csrToSigned req) $ PubKeyRSA pubKey -- sign CSR before verifying
```
