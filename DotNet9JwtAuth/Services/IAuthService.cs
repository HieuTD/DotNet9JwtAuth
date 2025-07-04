﻿using DotNet9JwtAuth.Entities;
using DotNet9JwtAuth.Entities.Models;

namespace DotNet9JwtAuth.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);
    }
}
