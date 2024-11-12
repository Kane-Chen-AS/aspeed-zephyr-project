# Certificate Chain Sample

The folder contains certificates and keys for reference.  

## Device ID Certificate Request
Sample Device ID certificate request(devid.req) is generated in first mutable code(mcuboot) and is signed by Device ID private key
Device ID private key is derived by CDI, in this sample, the value of CDI is all zero.  


## Root CA

```
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -subj "/C=TW/O=Aspeed/CN=Aspeed Root CA"
```

## Intermediate Certificate

```
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/C=TW/O=Aspeed/CN=Aspeed intermediate cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
```

## Leaf Certificate

```
openssl x509 -req -in devid.req -out leaf.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
```

devid.req is Device ID certificate signing request(DevID CSR), please refer to [Device ID Certificate Request](#device-id-certificate-request)

## Certificate chain

The following command generates sample certificate chain.

```
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in leaf.cert -out leaf.cert.der
cat ca.cert.der inter.cert.der leaf.cert.der > certchain.der
```

## Certificate Chain Update Flow

Programmer should perform following actions in MP flow :  
1. Hold soc reset pin, pull high gpior6 then release soc reset pin, AST1060 will be in FWSPI programming mode.
2. Get DeviceID CSR from AST1060 internal flash offset 0x1c000

    ```
    struct {
        u32    magic;
        u32    length;
        u8     data[4096];
        u8     hash[32];
        u8     pubkey[97];
        u8     cert_type;
    } PFR_DEVID_CERT_INFO;
    ```

3. Get CSR from `data[4096]`
4. Send CSR to HSM to generate certificate chain(cerchain.der)
5. Receive certchain.der from HSM
6. Regenerate PFR_DEVID_CERT_INFO
   - put cerchain.der in data[4096]
   - update length to the length of certchain.der
   - set cert_type to 0.
7. Erase ast1060 internal flash offset 0x1c000 - 0x1dfff
8. Write PFR_DEVID_CERT_INFO to ast1060 flash offset 0x1c00 - 0x1dfff


### Test Utility

certchain_bin_generator.py is a test utility to generate the certificate chain binary that mentioned in the step 6 of the above update flow.  
Please note that step 6 should be performed by the programmer or the manufacturing PC. This tool is intended to help developers generate test binaries during the development stage.  
Developers can program the binary to the certificate partition manually for testing attestation with the certificate chain.  

For example:
- Input Files:
  - certchain.der : certificate chain got from hsm
  - dev_id_pub.pem : device id public key that derived from CDI, in this sample, the CDI is all zero.

- Ouput Files:
  - certchain.bin : The certificate chain binary file, the format is mentioned in the step 2 of the above update flow.


- Usage:

  ```shell
  ~# python3 certchain_bin_generator.py certchain.der devid_pub.pem certchain.bin --verbose
  Verbose mode enabled.
  Reading certificate chain from file: certchain.der
  Loading public key from PEM file: devid_pub.pem
  Extracted public key (x, y):
  x (48 bytes): 95b1ccd0bc45269e1a8606daf14e3d5c21b31559ebaef4aa66ff9b4c9c0c3dd098ef8ae0e8d104bc58ed7249ab8da742
  y (48 bytes): 6d72bfa3a55159f45a2c8d1f7871dfe4525694367ef8628250c0af03bbac86316a024b5bac63050e53a168180eebd054
  Uncompressed public key (x + y) length: 97
  Uncompressed public key (x + y): 0495b1ccd0bc45269e1a8606daf14e3d5c21b31559ebaef4aa66ff9b4c9c0c3dd098ef8ae0e8d104bc58ed7249ab8da7426d72bfa3a55159f45a2c8d1f7871dfe4525694367ef8628250c0af03bbac86316a024b5bac63050e53a168180eebd054
  SHA-256 hash of certificate chain c3356d7f78bf41a7092ef103cd6974cdade01b7fdcdd5841ff2a9bf17f31871a
  Writing packed data to file: certchain.bin
  Packed data written to 'certchain.bin'.
  ```
