unit Crypt.XML.Sign;

interface

uses System.Classes, System.SysUtils, System.Generics.Collections, Winapi.Windows, Windows.Foundation, Windows.Security.Cryptography;

type
  TCertificate = class
  private
    FContext: PCERT_CONTEXT;
    FCertificateStore: HCERTSTORE;
    FKeySpec: CERT_KEY_SPEC;
    FPrivateKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
    FExpiry: TDateTime;
    FStart: TDateTime;
    FSerialNumber: String;
  public
    destructor Destroy; override;

    procedure Load(const Certificate: TBytes; const Password: String); overload;
    procedure Load(const FileName, Password: String); overload;
    procedure Load(const Stream: TStream; const Password: String); overload;

    property Context: PCERT_CONTEXT read FContext;
    property Expiry: TDateTime read FExpiry;
    property KeySpec: CERT_KEY_SPEC read FKeySpec;
    property PrivateKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE read FPrivateKey;
    property Start: TDateTime read FStart;
    property SerialNumber: String read FSerialNumber;
  end;

  TAlgorithm = class
  private
    FAlgorithm: CRYPT_XML_ALGORITHM;
  public
    constructor Create(const Algorithm: String);

    property Algorithm: CRYPT_XML_ALGORITHM read FAlgorithm write FAlgorithm;
  end;

  TTransform = class(TAlgorithm)
  end;

  TTransformBase64 = class(TTransform)
  public
    constructor Create;
  end;

  TTransformEveloped = class(TTransform)
  public
    constructor Create;
  end;

  TCanonicalizationMethod = class(TAlgorithm)
  end;

  TCanonicalizationC14C = class(TCanonicalizationMethod)
  public
    constructor Create;
  end;

  TCanonicalizationC14CWithComments = class(TCanonicalizationMethod)
  public
    constructor Create;
  end;

  TCanonicalizationExclusiveC14C = class(TCanonicalizationMethod)
  public
    constructor Create;
  end;

  TCanonicalizationExclusiveC14CWithComments = class(TCanonicalizationMethod)
  public
    constructor Create;
  end;

  TDigestMethod = class(TAlgorithm)
  end;

  TDigestMethodSHA1 = class(TDigestMethod)
  public
    constructor Create;
  end;

  TDigestMethodSHA256 = class(TDigestMethod)
  public
    constructor Create;
  end;

  TDigestMethodSHA384 = class(TDigestMethod)
  public
    constructor Create;
  end;

  TDigestMethodSHA512 = class(TDigestMethod)
  public
    constructor Create;
  end;

  TSignatureMethod = class(TAlgorithm)
  end;

  TSignatureMethodRSA_SHA1 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodDSA_SHA1 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodRSA_SHA256 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodRSA_SHA384 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodRSA_SHA512 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodECDSA_SHA1 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodECDSA_SHA256 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodECDSA_SHA384 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodECDSA_SHA512 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodHMAC_SHA1 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodHMAC_SHA256 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodHMAC_SHA384 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignatureMethodHMAC_SHA512 = class(TSignatureMethod)
  public
    constructor Create;
  end;

  TSignature = record
  public
    DigestValue: String;
    SignatureValue: String;
    X509Certificate: String;
  end;

  TSigner = class
  private
    FAlgorithms: TList<TAlgorithm>;
    FCanonicalizationMethod: TCanonicalizationMethod;
    FSignatureMethod: TSignatureMethod;
    FTransforms: TArray<CRYPT_XML_ALGORITHM>;
    FDigestMethod: TDigestMethod;

    function DoSign(const Certificate: TCertificate; const SignaturePath, URI, XML: String): Pointer;

    procedure AddAlgorithm(const Algorithm: TAlgorithm);
    procedure CheckReturn(const Value: HRESULT);
    procedure SetCanonicalizationMethod(const Value: TCanonicalizationMethod);
    procedure SetSignatureMethod(const Value: TSignatureMethod);
    procedure SetDigestMethod(const Value: TDigestMethod);
  public
    constructor Create;

    destructor Destroy; override;

    function Sign(const Certificate: TCertificate; const SignaturePath, URI, XML: String): TSignature;
    function SignXML(const Certificate: TCertificate; const SignaturePath, URI, XML: String): String;

    procedure AddTransform(const Transform: TAlgorithm);

    property CanonicalizationMethod: TCanonicalizationMethod read FCanonicalizationMethod write SetCanonicalizationMethod;
    property DigestMethod: TDigestMethod read FDigestMethod write SetDigestMethod;
    property SignatureMethod: TSignatureMethod read FSignatureMethod write SetSignatureMethod;
    property Transforms: TArray<CRYPT_XML_ALGORITHM> read FTransforms;
  end;

implementation

uses System.NetEncoding;

function CryptXmlGetSignature(hCryptXml: Pointer; out ppStruct: PCRYPT_XML_SIGNATURE): HRESULT; stdcall; external 'CRYPTXML.dll' name 'CryptXmlGetSignature';

type
  CallbackPointer = {$IF CompilerVersion < 37.0}PPointer{$ELSE}Pointer{$IFEND};

function WriteXML(Callback: CallbackPointer; Data: PByte; Size: Cardinal): HRESULT; stdcall;
begin
  PString(Callback^)^ := PString(Callback^)^ + TEncoding.UTF8.GetString(TBytes(Data), 0, Size);
  Result := S_OK;
end;

type
  PPCRYPT_XML_REFERENCE = ^PCRYPT_XML_REFERENCE;

{ TCertificate }

destructor TCertificate.Destroy;
begin
  if Assigned(FContext) then
    CertFreeCertificateContext(FContext);

  if Assigned(FCertificateStore) then
    CertCloseStore(FCertificateStore, 0);

  inherited;
end;

procedure TCertificate.Load(const FileName, Password: String);
begin
  var Stream := TFileStream.Create(FileName, fmOpenRead + fmShareDenyWrite);

  try
    Load(Stream, Password);
  finally
    Stream.Free;
  end;
end;

procedure TCertificate.Load(const Certificate: TBytes; const Password: String);

  function ConvertDate(const Date: FILETIME): TDateTime;
  var
    DateInfo: TFileTime absolute Date;
    SystemDateInfo: TSystemTime;

  begin
    Result := 0;

    if FileTimeToSystemTime(DateInfo, SystemDateInfo) then
      Result := SystemTimeToDateTime(SystemDateInfo);
  end;

  procedure LoadSerialNumber;
  begin
    var Number := Context.pCertInfo^.SerialNumber;

    SetLength(FSerialNumber, Number.cbData * 2);

    BinToHex(Number.pbData, PChar(FSerialNumber), Context.pCertInfo^.SerialNumber.cbData);

    FSerialNumber := SwapHexEndianness(FSerialNumber);
  end;

begin
  var Blob: CRYPT_INTEGER_BLOB;
  Blob.cbData := Length(Certificate);
  Blob.pbData := @Certificate[0];

  FCertificateStore := PFXImportCertStore(@Blob, PWSTR(Password), 0);

  if not Assigned(FCertificateStore) then
    RaiseLastOSError;

  FContext := CertFindCertificateInStore(FCertificateStore, X509_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, nil, nil);

  if not Assigned(FContext) then
    RaiseLastOSError;

  var CallerFree: BOOL := 0;

  if CryptAcquireCertificatePrivateKey(FContext, CRYPT_ACQUIRE_CACHE_FLAG, nil, FPrivateKey, @KeySpec, @CallerFree) = 0 then
    RaiseLastOSError;

  FExpiry := ConvertDate(FContext.pCertInfo^.NotAfter);
  FStart := ConvertDate(FContext.pCertInfo^.NotBefore);

  LoadSerialNumber;
end;

procedure TCertificate.Load(const Stream: TStream; const Password: String);
begin
  var ByteStream := TBytesStream.Create;

  try
    ByteStream.CopyFrom(Stream);

    Load(ByteStream.Bytes, Password);
  finally
    ByteStream.Free;
  end;
end;

{ TAlgorithm }

constructor TAlgorithm.Create(const Algorithm: String);
begin
  inherited Create;

  FAlgorithm.cbSize := SizeOf(FAlgorithm);
  FAlgorithm.Encoded.dwCharset := CRYPT_XML_CHARSET_AUTO;
  FAlgorithm.wszAlgorithm := PWSTR(Algorithm);
end;

{ TCanonicalizationC14C }

constructor TCanonicalizationC14C.Create;
begin
  inherited Create(wszURI_CANONICALIZATION_C14N);
end;

{ TCanonicalizationC14CWithComments }

constructor TCanonicalizationC14CWithComments.Create;
begin
  inherited Create(wszURI_CANONICALIZATION_C14NC);
end;

{ TCanonicalizationExclusiveC14C }

constructor TCanonicalizationExclusiveC14C.Create;
begin
  inherited Create(wszURI_CANONICALIZATION_EXSLUSIVE_C14N);
end;

{ TCanonicalizationExclusiveC14CWithComments }

constructor TCanonicalizationExclusiveC14CWithComments.Create;
begin
  inherited Create(wszURI_CANONICALIZATION_EXSLUSIVE_C14NC);
end;

{ TDigestMethodSHA1 }

constructor TDigestMethodSHA1.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_SHA1);
end;

{ TDigestMethodSHA256 }

constructor TDigestMethodSHA256.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_SHA256);
end;

{ TDigestMethodSHA384 }

constructor TDigestMethodSHA384.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_SHA384);
end;

{ TDigestMethodSHA512 }

constructor TDigestMethodSHA512.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_SHA512);
end;

{ TSignatureMethodRSA_SHA1 }

constructor TSignatureMethodRSA_SHA1.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_RSA_SHA1);
end;

{ TSignatureMethodDSA_SHA1 }

constructor TSignatureMethodDSA_SHA1.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_DSA_SHA1);
end;

{ TSignatureMethodRSA_SHA256 }

constructor TSignatureMethodRSA_SHA256.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_RSA_SHA256);
end;

{ TSignatureMethodRSA_SHA384 }

constructor TSignatureMethodRSA_SHA384.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_RSA_SHA384);
end;

{ TSignatureMethodRSA_SHA512 }

constructor TSignatureMethodRSA_SHA512.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_RSA_SHA512);
end;

{ TSignatureMethodECDSA_SHA1 }

constructor TSignatureMethodECDSA_SHA1.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_ECDSA_SHA1);
end;

{ TSignatureMethodECDSA_SHA256 }

constructor TSignatureMethodECDSA_SHA256.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_ECDSA_SHA256);
end;

{ TSignatureMethodECDSA_SHA384 }

constructor TSignatureMethodECDSA_SHA384.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_ECDSA_SHA384);
end;

{ TSignatureMethodECDSA_SHA512 }

constructor TSignatureMethodECDSA_SHA512.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_ECDSA_SHA512);
end;

{ TSignatureMethodHMAC_SHA1 }

constructor TSignatureMethodHMAC_SHA1.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_HMAC_SHA1);
end;

{ TSignatureMethodHMAC_SHA256 }

constructor TSignatureMethodHMAC_SHA256.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_HMAC_SHA256);
end;

{ TSignatureMethodHMAC_SHA384 }

constructor TSignatureMethodHMAC_SHA384.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_HMAC_SHA384);
end;

{ TSignatureMethodHMAC_SHA512 }

constructor TSignatureMethodHMAC_SHA512.Create;
begin
  inherited Create(wszURI_XMLNS_DIGSIG_HMAC_SHA512);
end;

{ TTransformBase64 }

constructor TTransformBase64.Create;
begin
  inherited Create(wszURI_XMLNS_TRANSFORM_BASE64);
end;

{ TTransformEveloped }

constructor TTransformEveloped.Create;
begin
  inherited Create(wszURI_XMLNS_TRANSFORM_ENVELOPED);
end;

{ TSigner }

procedure TSigner.AddAlgorithm(const Algorithm: TAlgorithm);
begin
  FAlgorithms.Add(Algorithm);
end;

procedure TSigner.AddTransform(const Transform: TAlgorithm);
begin
  AddAlgorithm(Transform);

  FTransforms := FTransforms + [Transform.Algorithm];
end;

procedure TSigner.CheckReturn(const Value: HRESULT);
begin
  if Failed(Value) then
    RaiseLastOSError(Value);
end;

constructor TSigner.Create;
begin
  inherited;

  FAlgorithms := TObjectList<TAlgorithm>.Create;

  CanonicalizationMethod := TCanonicalizationC14C.Create;
  DigestMethod := TDigestMethodSHA256.Create;
  SignatureMethod := TSignatureMethodRSA_SHA256.Create;
end;

destructor TSigner.Destroy;
begin
  FAlgorithms.Free;

  inherited;
end;

function TSigner.DoSign(const Certificate: TCertificate; const SignaturePath, URI, XML: String): Pointer;

  function GetTransforms: PCRYPT_XML_ALGORITHM;
  begin
    if Assigned(FTransforms) then
      Result := @Transforms[0]
    else
      Result := nil;
  end;

begin
  var CertificateBlob: CERT_BLOB;
  var EncodedXML: CRYPT_XML_BLOB;
  var KeyInfo: CRYPT_XML_KEYINFO_PARAM;
  var Path := PChar(SignaturePath);
  var Properties: CRYPT_XML_PROPERTY;
  var ReferenceValue: Pointer := nil;
  Result := nil;
  var XMLConverted := TEncoding.UTF8.GetBytes(XML);

  Properties.dwPropId := CRYPT_XML_PROPERTY_SIGNATURE_LOCATION;
  Properties.cbValue := SizeOf(LPCWSTR);
  Properties.pvValue := @Path;

  EncodedXML.cbData := Length(XMLConverted);
  EncodedXML.dwCharset := CRYPT_XML_CHARSET_UTF8;
  EncodedXML.pbData := @XMLConverted[0];

  FillChar(KeyInfo, SizeOf(KeyInfo), 0);

  KeyInfo.cCertificate := 1;
  KeyInfo.rgCertificate := @CertificateBlob;

  CertificateBlob.cbData := Certificate.Context.cbCertEncoded;
  CertificateBlob.pbData := Certificate.Context.pbCertEncoded;

  CheckReturn(CryptXmlOpenToEncode(nil, 0, nil, @Properties, 1, @EncodedXML, Result));

  CheckReturn(CryptXmlCreateReference(Result, 0, nil, PWSTR(URI), nil, @DigestMethod.Algorithm, Length(FTransforms), GetTransforms, ReferenceValue));

  CheckReturn(CryptXmlSign(Result, Certificate.PrivateKey, Certificate.KeySpec, 0, CRYPT_XML_KEYINFO_SPEC_PARAM, @KeyInfo, @SignatureMethod.Algorithm, @CanonicalizationMethod.Algorithm));
end;

procedure TSigner.SetCanonicalizationMethod(const Value: TCanonicalizationMethod);
begin
  FCanonicalizationMethod := Value;

  AddAlgorithm(Value);
end;

procedure TSigner.SetDigestMethod(const Value: TDigestMethod);
begin
  FDigestMethod := Value;

  AddAlgorithm(Value);
end;

procedure TSigner.SetSignatureMethod(const Value: TSignatureMethod);
begin
  FSignatureMethod := Value;

  AddAlgorithm(Value);
end;

function TSigner.Sign(const Certificate: TCertificate; const SignaturePath, URI, XML: String): TSignature;

  function ConvertToBytes(const Blob: CRYPT_INTEGER_BLOB): TBytes; overload;
  begin
    SetLength(Result, Blob.cbData);

    Move(Blob.pbData^, Result[0], Blob.cbData);
  end;

  function ConvertToBytes(const Blob: CRYPT_XML_DATA_BLOB): TBytes; overload;
  begin
    SetLength(Result, Blob.cbData);

    Move(Blob.pbData^, Result[0], Blob.cbData);
  end;

begin
  var Signature := DoSign(Certificate, SignaturePath, URI, XML);
  var SignatureInfo: PCRYPT_XML_SIGNATURE;

  CheckReturn(CryptXmlGetSignature(Signature, SignatureInfo));

  Result.DigestValue := TNetEncoding.Base64String.EncodeBytesToString(ConvertToBytes(PPCRYPT_XML_REFERENCE(SignatureInfo.SignedInfo.rgpReference)^.DigestValue));
  Result.SignatureValue := TNetEncoding.Base64String.EncodeBytesToString(ConvertToBytes(SignatureInfo.SignatureValue));
  Result.X509Certificate := TNetEncoding.Base64String.EncodeBytesToString(ConvertToBytes(SignatureInfo.pKeyInfo.rgKeyInfo.Anonymous.X509Data.rgX509Data.Anonymous.Certificate));
end;

function TSigner.SignXML(const Certificate: TCertificate; const SignaturePath, URI, XML: String): String;
begin
  var Properties: CRYPT_XML_PROPERTY;
  var ReturnValue := @Result;
  var ValueTrue: BOOL := 1;

  var Signature := DoSign(Certificate, SignaturePath, URI, XML);

  try
    Properties.dwPropId := CRYPT_XML_PROPERTY_DOC_DECLARATION;
    Properties.cbValue := SizeOf(ValueTrue);
    Properties.pvValue := @ValueTrue;

    CheckReturn(CryptXmlEncode(Signature, CRYPT_XML_CHARSET_UTF8, @Properties, 1, ReturnValue, WriteXML));
  finally
    CryptXmlClose(Signature);
  end;
end;

end.

