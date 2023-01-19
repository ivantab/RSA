using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using RSA.Api.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RSA.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class RSAController : ControllerBase
    {
        public RSAParameters _privateKey { get; set; }
//        MIIEpAIBAAKCAQEAvAm4Iz+LOjoljOsbyCC+shFx5zwAVOWQnc6dJeXIy0KUkDMW
//rbDUXBpyLmh3AgRV8AYb/bcc7+QCe4HXxy9cKqX+Ksu2XgADyqPBb6ikmfFEO4nK
//bMUdR7oj4IuSrQkLZgkSLSC1ntxAQgUpA+ZYSLJ+LczH64om/RBifAWzbNOvc0Q2
//GtU457It4+WUaA1Iin2lq0dOz998rKJB+ld7Gqc9JjfkurCH+sxC4omxR8C5lk6n
//Xxnx8/eO1DZdysRKTGTadDYX4hPiUdtoN5LpdtiETKtRkwrgRekNQWgHh37kWzgn
//aSQWekFIAPOpNYm1hpxBtCYQd7J8XoIRVzeHJQIDAQABAoIBAQCQ7yTg9k+IF91t
//mqIVRTf25H9Y7eSLi05GdESoO07jbHQ6GUa3pf5o53Fu19Iy2circuoMSyGgvaw0
//KkZ5HsX5kWww7EeqeHRzsnicae5FQbOH+JLv95az/IM+xhXODZSdlwxNgFK9GaLl
//wDh26wrNLdcX0imeISQgForycSp1C/kE13Q99weiFhyJN/+ZtvRECXf2+ZG3C2G2
//DuEUg0dBhUv315mAO7bVipf0QT97zSyfHHcS3DOhWY9fSUN+D4pxui9l0QsHZh0/
//rTcKyrUXX+TDOABu+W3xLJQ3nE+jodSW9sK/GEtmBjAW2Ms7yHEIJAmckZK3AmSZ
//sy5dCvQZAoGBAMeAluBQtQ+ZM4j/u+eUwmRnyzUlmrTyKtAhibRlexYQfpT1byh6
//rIhmmaZBNTC8hNn9pe9XKcSCr0Ku9RJjuCfN8+iycLpDKzxISygB6GqKfG1DJZT6
//0PFVeawJsTwqlYWBNBRgxInJw8Q5FC/hTe17yuJzQlBf0i5M0E1jEKPTAoGBAPFJ
///qEACqpUalGUDowrVE6yx2FOWvlSafq72JxScG3k8o3+bn/m/zBGax8apkoMaU9h
//9fPoGF0NerBiZBjRcqVM1/BOt5ttN5+cwNaVmkdzGaD614Y2Cp1iKpIkZxSA0LgX
//5fZb99PPjGnwePXDbMitiFrhwlYUdwa+NPaFJeYnAoGAcL99hTxXd39PnsdYvKJX
//0kLOlzSvYD/Ublfl6SvJCkk8IJcswSXDSDsj7s+/bdG9Cy3Mj50lH8fzoK4cFs6A
//jw5YIFRoXPwE/UamIvAhF8U4WM+v96hgWWPDJbU8kxJF+nNwqWue53g9yTGw9PZS
//AjsKCDy3Z5Efycbjmji4eL0CgYBwI019kcFjK9xFkaO5LSH/eUMETCAno0+xwb+H
//1yB9UlwP9eFw+/A5hWCfkgkafO4sgICIHKPGC0+rze5rQlwfyrjI7CyUxYuGWJme
//oOSUtD+C+1FTBKamQks6pERr2PontKOhfViOTfUZ/zKYNXzHPy8R3b4tt1EiByAi
//OftFHQKBgQCUtG8a1pCYgilvvork5LWy8oXsUFaUEZE65xGVLBpnxjrfDTL6H3nv
//W9+0+gYa9KlAGchq0WIb//QQ1yPRBTgHwSE9f7fG+LbT4AcHOcCLr8sMHsniXcxu
//4x/S4LTH4IJn2o7GR1AuYK1FMG7BzXwAMMYRbRxhlaPffbp4C1yx6w==


        public RSAParameters _publicKey { get; set; }
//        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAm4Iz+LOjoljOsbyCC+
//shFx5zwAVOWQnc6dJeXIy0KUkDMWrbDUXBpyLmh3AgRV8AYb/bcc7+QCe4HXxy9c
//KqX+Ksu2XgADyqPBb6ikmfFEO4nKbMUdR7oj4IuSrQkLZgkSLSC1ntxAQgUpA+ZY
//SLJ+LczH64om/RBifAWzbNOvc0Q2GtU457It4+WUaA1Iin2lq0dOz998rKJB+ld7
//Gqc9JjfkurCH+sxC4omxR8C5lk6nXxnx8/eO1DZdysRKTGTadDYX4hPiUdtoN5Lp
//dtiETKtRkwrgRekNQWgHh37kWzgnaSQWekFIAPOpNYm1hpxBtCYQd7J8XoIRVzeH
//JQIDAQAB

        public RSACryptoServiceProvider _csp { get; set; }

        private RSAService _service { get;set; } 

        public RSAController()
        {
            _csp= new RSACryptoServiceProvider();
            _privateKey = _csp.ExportParameters(true);
            _publicKey= _csp.ExportParameters(true);
            _service = new RSAService();
        }

        [HttpGet]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<string> GetData(string code)
        {
            //Generate private ublic key
            //string publicKey;
            //string privateKey;
            //using (var rsa = new RSACryptoServiceProvider(2048))
            //{
            //    publicKey = _service.MakePem(rsa.ExportSubjectPublicKeyInfo(), "PUBLIC KEY");
            //    privateKey = _service.MakePem(rsa.ExportRSAPrivateKey(), "RSA PRIVATE KEY");
            //}
            //return Ok(publicKey + privateKey);

            //var rsa = new RSACng();
            //rsa.KeySize = 3072;
            //string textEncripted = _service.Encrypt(code, _privateKey);
            //return Ok(textEncripted);
            // Console.WriteLine(rsa.KeySize); // prints 3072
            //Console.WriteLine(rsa.ExportParameters(false).Modulus.Length * 8); // also prints 3072
        }

        //[HttpGet("{id}")]
        //[ProducesResponseType(StatusCodes.Status200OK)]
        //[ProducesResponseType(StatusCodes.Status404NotFound)]
        //public  ActionResult<string> GetData(int id)
        //{
        //    string sourceData;
        //    string publicKey;
        //    string privateKey;
        //    string result =  string.Empty;  
        //    byte[] tmpSource;
        //    byte[] tmpHash;
        //    sourceData = "Datos de Prueba";
        //    try
        //    {

        //        tmpSource = ASCIIEncoding.ASCII.GetBytes(sourceData);
        //        RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
        //        rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(),2048));
        //        AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();
        //        RsaKeyParameters PrivateKeyParameter = (RsaKeyParameters)keyPair.Private;
        //        RsaKeyParameters PublicKeyParameter = (RsaKeyParameters)keyPair.Public;

        //        TextWriter textWriterPrivate = new StringWriter();
        //        PemWriter pemWriterPrivate = new PemWriter(textWriterPrivate);
        //        pemWriterPrivate.WriteObject(PrivateKeyParameter);
        //        pemWriterPrivate.Writer.Flush();
        //        privateKey = textWriterPrivate.ToString();

        //        TextWriter textWriterPublic = new StringWriter();                
        //        PemWriter pemWriterPublic = new PemWriter(textWriterPublic);
        //        pemWriterPublic.WriteObject(PublicKeyParameter);
        //        pemWriterPublic.Writer.Flush();
        //        publicKey = textWriterPublic.ToString();

        //        IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());
        //        cipher.Init(true, PublicKeyParameter);
        //        byte[] cipherText = cipher.ProcessBlock(tmpSource, 0, tmpSource.Length);
        //        result = Encoding.UTF8.GetString(cipherText);
        //        return Ok(publicKey);
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500);
        //    }          
        //}


    }
}