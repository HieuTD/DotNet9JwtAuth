using DotNet9JwtAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace DotNet9JwtAuth.Data
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options)
        {
        }
        public DbSet<User> Users { get; set; }
    }
}
