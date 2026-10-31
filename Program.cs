using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// BUSCA AS CONFIGURAÇÕES SE EXISTIREM, CASO CONTRÁRIO UTILIZA VALORES PADRÃO (FALLBACK)
var jwtIssuer = builder.Configuration["JwtSettings:Issuer"] ?? "MinhaApiApp";
var jwtAudience = builder.Configuration["JwtSettings:Audience"] ?? "MeusUsuariosApp";
var jwtSecret = builder.Configuration["JwtSettings:Secret"] ?? "ChaveSecretaSuperMisteriosaEComMaisDe32CaracteresParaOJwt";

var secretKey = Encoding.UTF8.GetBytes(jwtSecret);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(secretKey)
    };
});

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", (LoginRequest model) =>
{
    if (model.Usuario == "admin" && model.Senha == "senha123")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, model.Usuario),
                new Claim(ClaimTypes.Role, "Administrador")
            }),
            Expires = DateTime.UtcNow.AddHours(2),
            Issuer = jwtIssuer,
            Audience = jwtAudience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        return Results.Ok(new { Token = tokenString });
    }

    return Results.Unauthorized();
});

app.MapGet("/api/usuario/perfil", [Authorize] (ClaimsPrincipal user) =>
{
    var nomeUsuario = user.Identity?.Name;
    return Results.Ok(new { Mensagem = $"Olá, {nomeUsuario}! Você está autenticado com sucesso no sistema." });
});

app.Run();

public record LoginRequest(string Usuario, string Senha);
