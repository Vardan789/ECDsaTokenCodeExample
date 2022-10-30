using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

ECDsa keyExample = ECDsa.Create(new ECParameters
{
    Curve = ECCurve.NamedCurves.nistP521,
    D = Base64UrlEncoder.DecodeBytes("AU9bFHMSQ72Ku0i8I6wIeWnbeYu1o2OZ75DbxgWkZflVoiI_nS0yv57ilbfNrFItSXZR7nVwRQQDRUppaGxWgV4u"),
    Q = new ECPoint
    {
        X = Base64UrlEncoder.DecodeBytes("ARb2dI19fnKxQo4v2VNsSi7-R93ZT7NsXbnw89fM0IXa6N259xvhWDCMxO7ThRwbyQ9zWTRmsnIPl_VCI2JM2fGA"),
        Y = Base64UrlEncoder.DecodeBytes("AbbAS9z5-mto9idfTGYAJdOzPcG-3UT2OX8zLAMTomVzNPy_zDNOtKh4M-4FVX5lXo5_eJcNKtpDZnL-Uad9Yeso")
    }
});

string payload = string.Empty; //your  request  body

string createdToken = CreateToken(keyExample, payload);

bool tokenIsValid = ValidateToken(createdToken,keyExample);

Console.WriteLine($"Token - {createdToken}");

Console.WriteLine();

Console.WriteLine(@$"The token was  {(tokenIsValid ? string.Empty : "not")} valid");

Console.WriteLine();

string CreateToken(ECDsa key, string payloadData)
{
    var now = DateTime.UtcNow;
    JsonWebTokenHandler handler = new JsonWebTokenHandler();

    return handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "me",
        Audience = "you",
        Expires = now.AddMinutes(30),
        Claims = new Dictionary<string, object> { { "payload", payloadData } },
        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), "ES512")
    });
}

bool ValidateToken(string token,ECDsa key)
{
    JsonWebTokenHandler handler = new JsonWebTokenHandler();
    
    TokenValidationResult result = handler.ValidateToken(token, new TokenValidationParameters
    {
        ValidIssuer = "me",
        ValidAudience = "you",
        IssuerSigningKey = new ECDsaSecurityKey(key)
    });

    bool isValid = result.IsValid;

    return isValid;
}