using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using UserInfo.API.Models;

namespace UserInfo.API.Data
{
    public class UserInfoDBContext: IdentityDbContext<IdentityUser>
    {
        public UserInfoDBContext(DbContextOptions options) : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
