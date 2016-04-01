#include <cstring>
#include <x509.h>

using namespace v8;

// Field names that OpenSSL is missing.
static const char *MISSING[4][2] = {
  {
    "1.2.840.113533.7.65.0",
    "entrustVersionInfo"
  },
  
  {
    "1.3.6.1.4.1.311.60.2.1.1",
    "jurisdictionOfIncorpationLocalityName"
  },

  {
    "1.3.6.1.4.1.311.60.2.1.2",
    "jurisdictionOfIncorporationStateOrProvinceName"
  },

  {
    "1.3.6.1.4.1.311.60.2.1.3",
    "jurisdictionOfIncorporationCountryName"
  }
};

std::string parse_args(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() == 0) {
    Nan::ThrowTypeError("Must provide a certificate string.");
    return std::string();
  }

  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Certificate must be a string.");
    return std::string();
  }

  if (info[0]->ToString()->Length() == 0) {
    Nan::ThrowTypeError("Certificate argument provided, but left blank.");
    return std::string();
  }

  return *String::Utf8Value(info[0]->ToString());
}

NAN_METHOD(get_subject) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  Local<Value> key = Nan::New<String>("subject").ToLocalChecked();
  info.GetReturnValue().Set(
    Nan::Get(exports, key).ToLocalChecked());
}

NAN_METHOD(get_issuer) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  Local<Value> key = Nan::New<String>("issuer").ToLocalChecked();
  info.GetReturnValue().Set(
    Nan::Get(exports, key).ToLocalChecked());
}

NAN_METHOD(parse_cert) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  info.GetReturnValue().Set(exports);
}

/*
 * This is where everything is handled for both -0.11.2 and 0.11.3+.
 */
Local<Value> try_parse(const std::string& dataString) {
  Nan::EscapableHandleScope scope;
  const char* data = dataString.c_str();

  Local<Object> exports = Nan::New<Object>();
  X509 *cert;

  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    Nan::ThrowError("BIO doesn't support BIO_puts.");
    BIO_free(bio);
    return scope.Escape(exports);
  }
  else if (result <= 0) {
    Nan::ThrowError("No data was written to BIO.");
    BIO_free(bio);
    return scope.Escape(exports);
  }

  // Try raw read
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

  if (cert == NULL) {
    // Switch to file BIO
    bio = BIO_new(BIO_s_file());

    // If raw read fails, try reading the input as a filename.
    if (!BIO_read_filename(bio, data)) {
      Nan::ThrowError("File doesn't exist.");
      return scope.Escape(exports);
    }

    // Try reading the bio again with the file in it.
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (cert == NULL) {
      Nan::ThrowError("Unable to parse certificate.");
      return scope.Escape(exports);
    }
  }

  Nan::Set(exports, 
    Nan::New<String>("version").ToLocalChecked(), 
    Nan::New<Integer>((int) X509_get_version(cert)));
  Nan::Set(exports, 
    Nan::New<String>("subject").ToLocalChecked(), 
    parse_name(X509_get_subject_name(cert)));
  Nan::Set(exports, 
    Nan::New<String>("issuer").ToLocalChecked(), 
    parse_name(X509_get_issuer_name(cert)));
  Nan::Set(exports, 
    Nan::New<String>("serial").ToLocalChecked(), 
    parse_serial(X509_get_serialNumber(cert)));
  Nan::Set(exports, 
    Nan::New<String>("notBefore").ToLocalChecked(), 
    parse_date(X509_get_notBefore(cert)));
  Nan::Set(exports, 
    Nan::New<String>("notAfter").ToLocalChecked(), 
    parse_date(X509_get_notAfter(cert)));

  // Signature Algorithm
  int sig_alg_nid = OBJ_obj2nid(cert->sig_alg->algorithm);
  if (sig_alg_nid == NID_undef) {
    Nan::ThrowError("unable to find specified signature algorithm name.");
    return scope.Escape(exports);
  }
  Nan::Set(exports,
    Nan::New<String>("signatureAlgorithm").ToLocalChecked(),
    Nan::New<String>(OBJ_nid2ln(sig_alg_nid)).ToLocalChecked());

  // fingerPrint
  unsigned int md_size, idx;
  unsigned char md[EVP_MAX_MD_SIZE];
  if (X509_digest(cert, EVP_sha1(), md, &md_size)) {
    const char hex[] = "0123456789ABCDEF";
    char fingerprint[EVP_MAX_MD_SIZE * 3];
    for (idx = 0; idx < md_size; idx++) {
      fingerprint[3*idx] = hex[(md[idx] & 0xf0) >> 4];
      fingerprint[(3*idx)+1] = hex[(md[idx] & 0x0f)];
      fingerprint[(3*idx)+2] = ':';
    }

    if (md_size > 0) {
      fingerprint[(3*(md_size-1))+2] = '\0';
    } else {
      fingerprint[0] = '\0';
    }
    Nan::Set(exports, 
      Nan::New<String>("fingerPrint").ToLocalChecked(), 
      Nan::New<String>(fingerprint).ToLocalChecked());
  }

  // public key
  int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (pkey_nid == NID_undef) {
    Nan::ThrowError("unable to find specified public key algorithm name.");
    return scope.Escape(exports);
  }
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  Local<Object> publicKey = Nan::New<Object>();
  Nan::Set(publicKey, 
    Nan::New<String>("algorithm").ToLocalChecked(), 
    Nan::New<String>(OBJ_nid2ln(pkey_nid)).ToLocalChecked());

  if (pkey_nid == NID_rsaEncryption) {
    char *rsa_e_dec, *rsa_n_hex;
    RSA *rsa_key;
    rsa_key = pkey->pkey.rsa;
    rsa_e_dec = BN_bn2dec(rsa_key->e);
    rsa_n_hex = BN_bn2hex(rsa_key->n);
    Nan::Set(publicKey, 
      Nan::New<String>("e").ToLocalChecked(), 
      Nan::New<String>(rsa_e_dec).ToLocalChecked());
    Nan::Set(publicKey, 
      Nan::New<String>("n").ToLocalChecked(), 
      Nan::New<String>(rsa_n_hex).ToLocalChecked());
  }
  Nan::Set(exports, Nan::New<String>("publicKey").ToLocalChecked(), publicKey);
  EVP_PKEY_free(pkey);

  // Extensions
  Local<Object> extensions(Nan::New<Object>());
  STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
  int num_of_exts;
  int index_of_exts;
  if (exts) {
    num_of_exts = sk_X509_EXTENSION_num(exts);
  } else {
    num_of_exts = 0;
  }

  // IFNEG_FAIL(num_of_exts, "error parsing number of X509v3 extensions.");

  for (index_of_exts = 0; index_of_exts < num_of_exts; index_of_exts++) {
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, index_of_exts);
    // IFNULL_FAIL(ext, "unable to extract extension from stack");

    BIO *ext_bio = BIO_new(BIO_s_mem());
    // IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
    if (!X509V3_EXT_print(ext_bio, ext, 0, 0)) {
      M_ASN1_OCTET_STRING_print(ext_bio, ext->value);
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_CLOSE);

    char *data = (char*) malloc(bptr->length + 1);
    BUF_strlcpy(data, bptr->data, bptr->length + 1);
    data = trim(data, bptr->length);

    BIO_free(ext_bio);

    int nid = OBJ_obj2nid(ext->object);
    switch (nid) {
      case NID_undef: {
        char extname[100];
        OBJ_obj2txt(extname, 100, (const ASN1_OBJECT *) ext->object, 1);
        Nan::Set(extensions,
          Nan::New<String>(real_name(extname)).ToLocalChecked(),
          Nan::New<String>(data).ToLocalChecked());
        break;
      }
      case NID_subject_alt_name: {
        const char *c_ext_name = OBJ_nid2ln(nid);
        // IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
        Nan::Set(extensions,
          Nan::New<String>(c_ext_name).ToLocalChecked(),
          parse_subject_alt_names(ext));
        break;
      }
      default: {
        const char *c_ext_name = OBJ_nid2ln(nid);
        // IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
        Nan::Set(extensions,
          Nan::New<String>(real_name((char*)c_ext_name)).ToLocalChecked(),
          Nan::New<String>(data).ToLocalChecked());
      }
    }
  }
  Nan::Set(exports,
    Nan::New<String>("extensions").ToLocalChecked(), extensions);

  X509_free(cert);
  BIO_free(bio);
  
  return scope.Escape(exports);
}

Local<Value> parse_serial(ASN1_INTEGER *serial) {
  Nan::EscapableHandleScope scope;
  Local<String> serialNumber;
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
  char *hex = BN_bn2hex(bn);

  serialNumber = Nan::New<String>(hex).ToLocalChecked();
  BN_free(bn);
  OPENSSL_free(hex);
  return scope.Escape(serialNumber);
}

Local<Value> parse_date(ASN1_TIME *date) {
  Nan::EscapableHandleScope scope;
  BIO *bio;
  BUF_MEM *bm;
  char formatted[64];
  Local<Value> args[1];

  formatted[0] = '\0';
  bio = BIO_new(BIO_s_mem());
  ASN1_TIME_print(bio, date);
  BIO_get_mem_ptr(bio, &bm);
  BUF_strlcpy(formatted, bm->data, bm->length + 1);
  BIO_free(bio);
  args[0] = Nan::New<String>(formatted).ToLocalChecked();

  Local<Object> global = Nan::GetCurrentContext()->Global();
  Local<Object> DateObject = Nan::Get(global, 
    Nan::New<String>("Date").ToLocalChecked()).ToLocalChecked()->ToObject();
  return scope.Escape(DateObject->CallAsConstructor(1, args));
}

Local<Object> parse_name(X509_NAME *subject) {
  Nan::EscapableHandleScope scope;
  Local<Object> cert = Nan::New<Object>();
  int i, length;
  ASN1_OBJECT *entry;
  unsigned char *value;
  char buf[255];
  length = X509_NAME_entry_count(subject);
  for (i = 0; i < length; i++) {
    entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i));
    OBJ_obj2txt(buf, 255, entry, 0);
    value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
    Nan::Set(cert,
      Nan::New<String>(real_name(buf)).ToLocalChecked(),
      Nan::New<String>((const char*) value).ToLocalChecked());
  }
  return scope.Escape(cert);
}

Local<Object> parse_subject_alt_names(X509_EXTENSION *ext) {
  Nan::EscapableHandleScope scope;
  Local<Object> subAltNames = Nan::New<Object>();
  Local<Array> email = Nan::New<Array>();
  Local<Array> dns = Nan::New<Array>();
  Local<Array> dirName = Nan::New<Array>();
  Local<Array> uri = Nan::New<Array>();
  Local<Array> ipaddr = Nan::New<Array>();
  Local<Array> rid = Nan::New<Array>();

  const unsigned char *pp = ext->value->data;
  GENERAL_NAMES *names = d2i_GENERAL_NAMES(NULL, &pp, ext->value->length);
  if (names != NULL) {
    int i;
    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
      GENERAL_NAME *current = sk_GENERAL_NAME_value(names, i);
      switch (current->type) {
        case GEN_OTHERNAME: {
          int nid = OBJ_obj2nid(current->d.otherName->type_id);
          if (nid == NID_undef) {
            Nan::Set(subAltNames,
              Nan::New<String>("otherName").ToLocalChecked(),
              Nan::New<String>("<unsupported>").ToLocalChecked());
          } else {
            const char *name = OBJ_nid2sn(nid);
            ASN1_STRING *asn1 = current->d.otherName->value->value.asn1_string;
            char *value = (char*) ASN1_STRING_data(asn1);
            if (ASN1_STRING_length(asn1) != (int) strlen(value)) {
              Nan::ThrowError("Malformed otherName field.");
              return scope.Escape(subAltNames);
            }
            Nan::Set(subAltNames,
              Nan::New<String>(name).ToLocalChecked(),
              Nan::New<String>(value).ToLocalChecked());
          }
          break;
        }
        case GEN_EMAIL: {
          char *name = (char*) ASN1_STRING_data(current->d.rfc822Name);
          if (ASN1_STRING_length(current->d.rfc822Name) != (int) strlen(name)) {
            Nan::ThrowError("Malformed email field.");
            return scope.Escape(subAltNames);
          }
          Nan::Set(email,
            email->Length(),
            Nan::New<String>(name).ToLocalChecked());
          break;
        }
        case GEN_DNS: {
          char *name = (char*) ASN1_STRING_data(current->d.dNSName);
          if (ASN1_STRING_length(current->d.dNSName) != (int) strlen(name)) {
            Nan::ThrowError("Malformed DNS field.");
            return scope.Escape(subAltNames);
          }
          Nan::Set(dns,
            dns->Length(),
            Nan::New<String>(name).ToLocalChecked());
          break;
        }
        case GEN_X400: {
          Nan::Set(subAltNames,
            Nan::New<String>("X400Name").ToLocalChecked(),
            Nan::New<String>("<unsupported>").ToLocalChecked());
          break;
        }
        case GEN_DIRNAME: {
          char oline[256];
          X509_NAME_oneline(current->d.dirn, oline, 256);
          Nan::Set(dirName,
            dirName->Length(),
            Nan::New<String>(oline).ToLocalChecked());
          break;
        }
        case GEN_EDIPARTY: {
          Nan::Set(subAltNames,
            Nan::New<String>("EdiPartyName").ToLocalChecked(),
            Nan::New<String>("<unsupported>").ToLocalChecked());
          break;
        }
        case GEN_URI: {
          char *name = (char*) ASN1_STRING_data(current->d.uniformResourceIdentifier);
          if (ASN1_STRING_length(current->d.uniformResourceIdentifier) != (int) strlen(name)) {
            Nan::ThrowError("Malformed URI field.");
            return scope.Escape(subAltNames);
          }
          Nan::Set(uri,
            uri->Length(),
            Nan::New<String>(name).ToLocalChecked());
          break;
        }
        case GEN_IPADD: {
          // Based on/pulled from OpenSSL v3_alt.c
          char oline[256] = "<invalid>";
          char htmp[5];
          unsigned char *p = current->d.ip->data;
          if (current->d.ip->length == 4) {
            BIO_snprintf(oline, sizeof(oline), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
          } else if (current->d.ip->length == 16) {
            oline[0] = 0;
            for (i = 0; i < 8; i++) {
              BIO_snprintf(htmp, sizeof htmp, "%X", p[0] << 8 | p[1]);
              p += 2;
              strcat(oline, htmp);
              if (i != 7)
                strcat(oline, ":");
            }
          }
          Nan::Set(ipaddr,
            ipaddr->Length(),
            Nan::New<String>(oline).ToLocalChecked());
          break;
        }
        case GEN_RID: {
          char oline[256];
          i2t_ASN1_OBJECT(oline, 256, current->d.rid);
          Nan::Set(rid,
            rid->Length(),
            Nan::New<String>(oline).ToLocalChecked());
          break;
        }
      }
    }

    if (email->Length() > 0)
      Nan::Set(subAltNames, Nan::New<String>("email").ToLocalChecked(), email);
    if (dns->Length() > 0)
      Nan::Set(subAltNames, Nan::New<String>("dns").ToLocalChecked(), dns);
    if (dirName->Length() > 0)
      Nan::Set(subAltNames, Nan::New<String>("dirName").ToLocalChecked(), dirName);
    if (uri->Length() > 0)
      Nan::Set(subAltNames, Nan::New<String>("uri").ToLocalChecked(), uri);
    if (ipaddr->Length() > 0)
      Nan::Set(subAltNames, Nan::New<String>("ips").ToLocalChecked(), ipaddr);
  }
  return scope.Escape(subAltNames);
}

// Fix for missing fields in OpenSSL.
char* real_name(char *data) {
  int i, length = (int) sizeof(MISSING) / sizeof(MISSING[0]);

  for (i = 0; i < length; i++) {
    if (strcmp(data, MISSING[i][0]) == 0)
      return (char*) MISSING[i][1];
  }

  return data;
}

char* trim(char *data, int len) {
  if (data[0] == '\n' || data[0] == '\r') {
    data = data+1;
  }
  else if (len > 1 && (data[len-1] == '\n' || data[len-1] == '\r')) {
    data[len-1] = (char) 0;
  }
  else if (len > 0 && (data[len] == '\n' || data[len] == '\r')) {
    data[len] = (char) 0;
  }
  else {
    return data;
  }

  return trim(data, len - 1);
}
