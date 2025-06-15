using DotNet9JwtAuth.Entities;
using DotNet9JwtAuth.Entities.Models;
using DotNet9JwtAuth.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace DotNet9JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IAuthService _service;
        public AuthController(IAuthService service)
        {
            _service = service;
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register (UserDto request)
        {
            var user = await _service.RegisterAsync(request);

            if(user is null)
            {
                return BadRequest("Username already exists");
            }
            return Ok(user);
        }

        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login (UserDto request)
        {
            var token = await _service.LoginAsync(request);
            if (token is null)
            {
                return BadRequest("Invalid username or password");
            }
            return Ok(token);
        }

    }
}
