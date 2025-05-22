using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Mvc;
namespace ToDoAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SecretsController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public SecretsController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("get-secrets")]
        public async Task<IActionResult> GetSecretsAsync()
        {
            string keyVaultUrl = _configuration["AzureKeyVault:VaultUrl"];
            var secretKeys = _configuration.GetSection("AzureKeyVault:Secrets").Get<string[]>();

            if (string.IsNullOrWhiteSpace(keyVaultUrl) || secretKeys == null || secretKeys.Length == 0)
            {
                return BadRequest("Invalid Key Vault configuration.");
            }

            var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
            var secrets = new Dictionary<string, string>();

            foreach (var key in secretKeys)
            {
                try
                {
                    KeyVaultSecret secret = await client.GetSecretAsync(key);
                    secrets[key] = secret.Value;
                }
                catch (Exception ex)
                {
                    secrets[key] = $"Error: {ex.Message}";
                }
            }

            return Ok(secrets);
        }
    }
}
