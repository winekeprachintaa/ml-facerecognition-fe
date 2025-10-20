using Microsoft.AspNetCore.StaticFiles;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// ===== Tambahan: CORS longgar untuk dev (opsional; aman karena frontend sama origin) =====
builder.Services.AddCors(o =>
{
    o.AddDefaultPolicy(p =>
        p.AllowAnyOrigin()
         .AllowAnyHeader()
         .AllowAnyMethod());
});

// ===== Tambahan: HttpClient untuk proxy ke Face API (bypass sertifikat self-signed saat Development) =====
builder.Services.AddHttpClient("faceApi")
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var h = new HttpClientHandler();
        if (builder.Environment.IsDevelopment())
        {
            // Hanya untuk DEV: terima sertifikat self-signed di 192.168.x.x
            h.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
        return h;
    });

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors();                // <— aktifkan CORS jika perlu
app.UseDefaultFiles();
app.UseStaticFiles();

// ===== MIME .onnx tetap =====
var provider = new FileExtensionContentTypeProvider();
provider.Mappings[".onnx"] = "application/onnx";

app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = provider
});

// ==================== PROXY ENDPOINT ====================
// Frontend cukup POST ke /proxy/recognition/check (multipart/form-data)
// Field file boleh bernama apa saja; jika tidak ada, dikasih nama 'file' default.
app.MapPost("/proxy/api/v1/recognition/check", async (HttpContext ctx, IHttpClientFactory factory, ILogger<Program> log) =>
{
    try
    {
        var client = factory.CreateClient("faceApi");
        client.DefaultRequestHeaders.Accept.Clear();
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // Baca form body dari request browser
        var form = await ctx.Request.ReadFormAsync();

        using var mp = new MultipartFormDataContent();

        // Kirim semua field non-file apa adanya
        foreach (var kv in form)
        {
            if (form.Files.Any(f => f.Name == kv.Key)) continue;
            foreach (var v in kv.Value)
                mp.Add(new StringContent(v ?? string.Empty), kv.Key);
        }

        // Sertakan file (gunakan nama asli; jika kosong, pakai "file")
        if (form.Files.Count == 0)
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync("{\"status\":\"error\",\"message\":\"no file provided\"}");
            return;
        }

        foreach (var file in form.Files)
        {
            var name = string.IsNullOrWhiteSpace(file.Name) ? "file" : file.Name;
            var stream = file.OpenReadStream();
            var sc = new StreamContent(stream);
            sc.Headers.ContentType = new MediaTypeHeaderValue(file.ContentType ?? "application/octet-stream");
            mp.Add(sc, name, file.FileName);
        }

        // Kirim ke API LAN
        var upstreamUrl = "https://192.168.100.181:8080/api/v1/recognition/check";
        using var upstream = await client.PostAsync(upstreamUrl, mp);

        // Teruskan status + body ke browser
        ctx.Response.StatusCode = (int)upstream.StatusCode;
        ctx.Response.ContentType = upstream.Content.Headers.ContentType?.ToString() ?? "application/json";

        // (opsional) log ringkas
        log.LogInformation("Proxy -> {Url} => {Status}", upstreamUrl, upstream.StatusCode);

        using var body = await upstream.Content.ReadAsStreamAsync();
        await body.CopyToAsync(ctx.Response.Body);
    }
    catch (Exception ex)
    {
        // Jangan biarkan exception meledak ke 500 generik tanpa konteks
        var logId = Guid.NewGuid().ToString("N");
        (ctx.RequestServices.GetRequiredService<ILogger<Program>>())
            .LogError(ex, "Proxy error ({LogId})", logId);

        ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync($"{{\"status\":\"error\",\"message\":\"proxy failed ({logId}): {Escape(ex.Message)}\"}}");
    }
}).DisableAntiforgery();

// Ping sederhana untuk test hidup
app.MapGet("/proxy/ping", () => Results.Ok(new { ok = true }));

app.MapFallbackToFile("index.html");

app.Run();

static string Escape(string s)
{
    return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
