using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Extensions.Primitives;
using System.Security.Cryptography.X509Certificates;

namespace InboundCertificateValidationRepro
{
    public static class Function1
    {
        private static string CertThumbprint = "<REPLACE_WITH_CERTIFICATE_THUMBPRINT>";
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            {
                log.LogInformation("C# HTTP trigger RandomString processed a request.");

                StringValues cert;
                if (req.Headers.TryGetValue("X-ARR-ClientCert", out cert))
                {
                    byte[] clientCertBytes = Convert.FromBase64String(cert[0]);
                    X509Certificate2 clientCert = new X509Certificate2(clientCertBytes);

                    // Validate Thumbprint
                    if (clientCert.Thumbprint != CertThumbprint)
                    {
                        return new BadRequestObjectResult("A valid client certificate is not used");
                    }

                    // Validate NotBefore and NotAfter
                    if (DateTime.Compare(DateTime.UtcNow, clientCert.NotBefore) < 0
                                || DateTime.Compare(DateTime.UtcNow, clientCert.NotAfter) > 0)
                    {
                        return new BadRequestObjectResult("client certificate not in alllowed time interval");
                    }

                    // Add further validation of certificate as required.
                    
                    return new OkObjectResult("Certificate was valid!!!");
                }

                return new BadRequestObjectResult("A valid client certificate is not found");
            }
        }
    }
}
