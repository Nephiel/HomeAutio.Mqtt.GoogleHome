using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using HomeAutio.Mqtt.GoogleHome.Models.GoogleHomeGraph;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

using System.IO;
using System.Threading;
using Google.Apis.Auth.OAuth2;

namespace HomeAutio.Mqtt.GoogleHome
{
    /// <summary>
    /// Google Home Graph API client.
    /// </summary>
    public class GoogleHomeGraphClient
    {
        private const string _googleHomeGraphApiReportStateUri = "https://homegraph.googleapis.com/v1/devices:reportStateAndNotification";
        private const string _googleHomeGraphApiRequestSyncUri = "https://homegraph.googleapis.com/v1/devices:requestSync";
        private const string _homeGraphScope = "https://www.googleapis.com/auth/homegraph";

        private readonly ILogger<GoogleHomeGraphClient> _log;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly string _agentUserId;
        private readonly string _googleHomeGraphApiKey;
        private readonly string _serviceAccountFilePath;

        private ServiceAccountCredential _saCredential;
        private AccessTokenResponse _accessToken;
        private object _tokenRefreshLock = new object();

        /// <summary>
        /// Initializes a new instance of the <see cref="GoogleHomeGraphClient"/> class.
        /// </summary>
        /// <param name="logger">Logging instance.</param>
        /// <param name="httpClientFactory">HttpClient factory.</param>
        /// <param name="serviceAccountFilePath">Service account JSON file path.</param>
        /// <param name="agentUserId">Agent user id.</param>
        /// <param name="googleHomeGraphApiKey">Google Home Graph API key.</param>
        public GoogleHomeGraphClient(
            ILogger<GoogleHomeGraphClient> logger,
            IHttpClientFactory httpClientFactory,
            string serviceAccountFilePath,
            string agentUserId,
            string googleHomeGraphApiKey)
        {
            _log = logger;
            _httpClientFactory = httpClientFactory;
            _agentUserId = agentUserId;
            _googleHomeGraphApiKey = googleHomeGraphApiKey;
            _serviceAccountFilePath = serviceAccountFilePath;
        }

        /// <summary>
        /// Send Google Home Graph request sync.
        /// </summary>
        /// <returns>An awaitable <see cref="Task"/>.</returns>
        public async Task RequestSyncAsync()
        {
            // If no api key has been provided, don't attempt to call
            if (string.IsNullOrEmpty(_googleHomeGraphApiKey))
            {
                _log.LogWarning("REQUEST_SYNC triggered but Google Home Graph API was blank");
                return;
            }

            var request = new Request
            {
                AgentUserId = _agentUserId
            };

            var requestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(_googleHomeGraphApiRequestSyncUri + "?key=" + _googleHomeGraphApiKey),
                Content = new StringContent(JsonConvert.SerializeObject(request))
            };

            var client = _httpClientFactory.CreateClient();
            var response = await client.SendAsync(requestMessage);

            _log.LogInformation("Sent REQUEST_SYNC to Google Home Graph");

            string rep = await response.Content.ReadAsStringAsync();
            _log.LogDebug("Got response to REQUEST_SYNC from Google Home Graph: " + rep);

        }

        /// <summary>
        /// Send updates to the Google Home Graph.
        /// </summary>
        /// <param name="devices">Devices updated.</param>
        /// <param name="stateCache">Current state cache.</param>
        /// <returns>An awaitable <see cref="Task"/>.</returns>
        public async Task SendUpdatesAsync(IList<Models.State.Device> devices, IDictionary<string, string> stateCache)
        {
            // If no service account has been provided, don't attempt to call
            if (_serviceAccountFilePath == null)
            {
                _log.LogWarning("WillReportState triggered but Google Home Graph serviceAccountFile setting was blank, or the file didn't exist");
                return;
            }

            // Ensure access token is available
            if (_accessToken == null || _accessToken.ExpiresAt <= DateTime.Now.AddMinutes(-1))
            {
                _log.LogDebug("Retrieving access token");
                lock (_tokenRefreshLock)
                {
                    try
                    {
                        _accessToken = GetAccessToken(ConstructJwt()).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        _log.LogError("SendUpdatesAsync Exception: {0}.", ex.Message);
                        _accessToken = null;
                    }
                }
            }

            if (_accessToken == null)
            {
                _log.LogWarning("AccessToken is unavailable, aborting");
            }
            else
            {
                _log.LogDebug("Building request");
                var request = new Request
                {
                    RequestId = Guid.NewGuid().ToString(),
                    AgentUserId = _agentUserId,
                    Payload = new QueryResponsePayload
                    {
                        Devices = new Devices
                        {
                            States = devices.ToDictionary(
                                device => device.Id,
                                device => device.GetGoogleState(stateCache))
                        }
                    }
                };

                _log.LogDebug("Building requestMessage");
                string contentString = JsonConvert.SerializeObject(request);
                _log.LogDebug("Content: " + contentString);
                var requestMessage = new HttpRequestMessage
                {
                    Method = HttpMethod.Post,
                    RequestUri = new Uri(_googleHomeGraphApiReportStateUri),
                    Content = new StringContent(contentString)
                };

                _log.LogDebug("Adding access token");
                // Add access token
                requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _accessToken.AccessToken);

                _log.LogDebug("Creating client");
                var client = _httpClientFactory.CreateClient();
                _log.LogDebug("Requesting response");
                var response = await client.SendAsync(requestMessage);

                _log.LogInformation("Sent update to Google Home Graph for devices: " + string.Join(", ", devices.Select(x => x.Id)));

                string rep = await response.Content.ReadAsStringAsync();
                _log.LogDebug("Got response from Google Home Graph for devices: " + rep);
            }
        }

        /// <summary>
        /// Gets an access token using the passed JWT request.
        /// </summary>
        /// <param name="jwt">JWT request.</param>
        /// <returns>An <see cref="AccessTokenResponse"/>.</returns>
        private async Task<AccessTokenResponse> GetAccessToken(string jwt)
        {
            _log.LogDebug("Get/Refresh access token");

            var paramaters = new Dictionary<string, string>();
            paramaters.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            paramaters.Add("assertion", ConstructJwt());

            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(_saCredential.TokenServerUrl),
                Content = new FormUrlEncodedContent(paramaters)
            };

            var client = _httpClientFactory.CreateClient();
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var accessToken = await response.Content.ReadAsAsync<AccessTokenResponse>();

            _log.LogDebug("Received access token: " + accessToken);

            return accessToken;
        }

        /// <summary>
        /// Gets a JWT token.
        /// </summary>
        /// <returns>A JWT token.</returns>
        private string ConstructJwt()
        {
            // Read credentials from the credentials .json file.
            using (var fs = new FileStream(_serviceAccountFilePath, FileMode.Open, FileAccess.Read))
            {
                _saCredential = ServiceAccountCredential.FromServiceAccountData(fs);
            }

            // Encryption algorithm must be RSA SHA-256, according to
            // https://developers.google.com/identity/protocols/OAuth2ServiceAccount
            var signingCredentials = new SigningCredentials(
                new RsaSecurityKey(_saCredential.Key),
                SecurityAlgorithms.RsaSha256);

            // Create auth token
            var claims = new List<Claim> { new Claim("scope", _homeGraphScope) };
            var header = new JwtHeader(signingCredentials);
            var payload = new JwtPayload(
                _saCredential.Id,
                _saCredential.TokenServerUrl,
                claims,
                DateTime.Now,
                DateTime.Now.AddHours(1),
                DateTime.Now);
            var jwtToken = new JwtSecurityToken(header, payload);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(jwtToken);

            _log.LogDebug("Built JWT token: " + token);

            return token;
        }
    }
}
