using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Nancy.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Weather.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration) 
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Burada ilk olarak kullanıcı adı ile şifre oluştururuz.(statik olmayarak.Farklı kullanıcı adı ve şifre oluşturabiliriz.)
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        /// <summary>
        /// İkinci olarak buraya gelip kullanıcı adı ile şifreyle token alırız. Daha sonra aldığımız token ile sağ üsteki "Authorize"'ye gelip ("bearer {token}") ile bu şekilde token'ı yapıştırırız. 
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        /// <summary>
        /// Burada da apimize girilen şehir isminin hava tahminin sonucunu dönüş yapar.
        /// </summary>
        /// <param name="location"></param>
        /// <returns></returns>
        [HttpPost("GetCurrentWeatherByLocation"), Authorize]
        public async Task<ActionResult<string>> GetCurrentWeatherByLocation(string location)
        {
            string appId = "d7713e1104390b4778722ea1d286bbe0";
            string url = string.Format("https://api.openweathermap.org/geo/1.0/direct?q={0}&appid={1}", location, appId);
            using (WebClient client = new WebClient())
            {
                string json = client.DownloadString(url);
                string result = json.Remove(0, 1);
                string result2 = result.Remove(result.Length - 1);
                //Converting to OBJECT from JSON string.
                RootObject weatherInfo = (new JavaScriptSerializer()).Deserialize<RootObject>(result2);

                //Special VIEWMODEL design to send only required fields not all fields which received from 
                //www.openweathermap.org api
                ResultViewModel rslt = new ResultViewModel();

                rslt.Lat = Convert.ToString(weatherInfo.lat);
                rslt.Lon = Convert.ToString(weatherInfo.lon);

                string url1 = string.Format("https://api.openweathermap.org/data/2.5/weather?lat={0}&lon={1}&appid={2}&lang=tr", rslt.Lat, rslt.Lon, appId);
                string json1 = client.DownloadString(url1);

                RootObject weatherInfo1 = (new JavaScriptSerializer()).Deserialize<RootObject>(json1);

                ResultViewModel rslt1 = new ResultViewModel();
                rslt1.Description = weatherInfo1.weather[0].description;
                rslt1.Temp = Convert.ToString(((int)weatherInfo1.main.temp - 273) + " °C");
                rslt1.Country = weatherInfo1.sys.country;
                rslt1.City = weatherInfo1.name + "," + " " + rslt1.Country;


                return (rslt1.Temp) + "," + " " + (rslt1.Description) + "," + " " + (rslt1.City);
            }

        }



    }
    public class ResultViewModel
    {
        public string Lat { get; set; }
        public string Lon { get; set; }
        public string Temp { get; set; }
        public string Description { get; set; }
        public string City { get; set; }
        public string Country { get; set; }
    }

    public class Weather
    {
        public string description { get; set; }
    }

    public class Main
    {
        public double temp { get; set; }
    }

    public class Sys
    {
        public string country { get; set; }
    }
    public class RootObject
    {
        public double lon { get; set; }
        public double lat { get; set; }
        public List<Weather> weather { get; set; }
        public Main main { get; set; }
        public Sys sys { get; set; }
        public string name { get; set; }
    }
}
